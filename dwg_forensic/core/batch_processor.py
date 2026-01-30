"""Batch processing for analyzing multiple DWG files in parallel.

This module provides multiprocessing-based batch analysis capabilities for
processing directories of DWG files. Designed for Windows compatibility using
ProcessPoolExecutor (no fork()).

Features:
- Parallel processing with configurable worker count
- Progress tracking with tqdm
- Individual file error isolation (one failure doesn't crash batch)
- Result aggregation and summary statistics
- Graceful degradation for unsupported files
"""

import logging
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

from tqdm import tqdm

from dwg_forensic.core.analyzer import ForensicAnalyzer
from dwg_forensic.models import ForensicAnalysis, RiskLevel
from dwg_forensic.utils.exceptions import DWGForensicError


logger = logging.getLogger(__name__)


@dataclass
class BatchFileResult:
    """Result of analyzing a single file in a batch.

    Attributes:
        file_path: Path to the analyzed file
        success: Whether analysis succeeded
        analysis: ForensicAnalysis result (None if failed)
        error: Error message (None if successful)
        error_type: Type of error exception (None if successful)
    """
    file_path: Path
    success: bool
    analysis: Optional[ForensicAnalysis] = None
    error: Optional[str] = None
    error_type: Optional[str] = None


@dataclass
class BatchAnalysisResult:
    """Aggregated results from batch processing multiple DWG files.

    Attributes:
        total_files: Total number of files processed
        successful: Number of successfully analyzed files
        failed: Number of files that failed analysis
        results: List of successful ForensicAnalysis results
        failures: List of BatchFileResult objects for failed files
        aggregated_risk_score: Average risk score across all successful analyses
        risk_distribution: Count of files by risk level
        processing_time_seconds: Total processing time
        llm_result: Optional BatchLLMResult if LLM processing was enabled
        llm_enabled: Whether LLM processing was requested
    """
    total_files: int
    successful: int
    failed: int
    results: List[ForensicAnalysis] = field(default_factory=list)
    failures: List[BatchFileResult] = field(default_factory=list)
    aggregated_risk_score: float = 0.0
    risk_distribution: Dict[str, int] = field(default_factory=dict)
    processing_time_seconds: float = 0.0
    llm_result: Optional[Any] = None  # BatchLLMResult (avoid circular import)
    llm_enabled: bool = False


def _analyze_single_file(file_path: Path) -> BatchFileResult:
    """Worker function to analyze a single DWG file.

    This function is executed in a separate process via ProcessPoolExecutor.
    Must be a module-level function (not a method) for Windows multiprocessing.

    Args:
        file_path: Path to DWG file to analyze

    Returns:
        BatchFileResult with analysis results or error information
    """
    try:
        # Create analyzer instance (each worker gets its own)
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(file_path)

        return BatchFileResult(
            file_path=file_path,
            success=True,
            analysis=analysis,
        )

    except DWGForensicError as e:
        logger.warning(f"Forensic error analyzing {file_path.name}: {e}")
        return BatchFileResult(
            file_path=file_path,
            success=False,
            error=str(e),
            error_type=type(e).__name__,
        )

    except Exception as e:
        logger.error(f"Unexpected error analyzing {file_path.name}: {e}", exc_info=True)
        return BatchFileResult(
            file_path=file_path,
            success=False,
            error=f"Unexpected error: {e}",
            error_type=type(e).__name__,
        )


class BatchProcessor:
    """Batch processor for analyzing multiple DWG files in parallel.

    Uses ProcessPoolExecutor for Windows-compatible multiprocessing.
    Provides progress tracking and error isolation.
    """

    def __init__(self, num_workers: Optional[int] = None):
        """Initialize batch processor.

        Args:
            num_workers: Number of parallel workers (default: CPU count)
        """
        if num_workers is None:
            # Use CPU count, but cap at 8 to avoid overwhelming the system
            num_workers = min(multiprocessing.cpu_count(), 8)

        self.num_workers = max(1, num_workers)  # Minimum 1 worker
        logger.info(f"BatchProcessor initialized with {self.num_workers} workers")

    def process_directory(
        self,
        directory: Path,
        output_dir: Optional[Path] = None,
        recursive: bool = False,
        pattern: str = "*.dwg",
        with_llm: bool = False,
        llm_model: str = "mistral",
        risk_threshold: float = 0.3,
    ) -> BatchAnalysisResult:
        """Process all DWG files in a directory.

        Args:
            directory: Directory containing DWG files
            output_dir: Optional directory for individual JSON reports (not yet implemented)
            recursive: Whether to search subdirectories
            pattern: Glob pattern for finding DWG files (default: "*.dwg")
            with_llm: Enable LLM narrative generation (requires Ollama)
            llm_model: Model name for LLM generation (default: "mistral")
            risk_threshold: Minimum risk score for LLM processing (default: 0.3)

        Returns:
            BatchAnalysisResult with aggregated results

        Raises:
            ValueError: If directory doesn't exist or contains no matching files
        """
        import time

        start_time = time.time()

        # Validate directory
        if not directory.exists():
            raise ValueError(f"Directory does not exist: {directory}")

        if not directory.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")

        # Find all DWG files
        if recursive:
            files = list(directory.rglob(pattern))
        else:
            files = list(directory.glob(pattern))

        if not files:
            raise ValueError(f"No files matching '{pattern}' found in {directory}")

        logger.info(f"Found {len(files)} files to process in {directory}")

        # Process files in parallel
        results: List[BatchFileResult] = []

        with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(_analyze_single_file, file_path): file_path
                for file_path in files
            }

            # Progress bar
            with tqdm(total=len(files), desc="Analyzing DWG files", unit="file") as pbar:
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        results.append(result)

                        # Update progress bar with status
                        if result.success:
                            pbar.set_postfix(
                                success=sum(1 for r in results if r.success),
                                failed=sum(1 for r in results if not r.success),
                            )
                        else:
                            pbar.set_postfix(
                                success=sum(1 for r in results if r.success),
                                failed=sum(1 for r in results if not r.success),
                            )

                    except Exception as e:
                        # This should never happen (worker handles all exceptions)
                        logger.error(f"Future raised unexpected error for {file_path}: {e}")
                        results.append(
                            BatchFileResult(
                                file_path=file_path,
                                success=False,
                                error=f"Future error: {e}",
                                error_type="FutureError",
                            )
                        )

                    pbar.update(1)

        # Aggregate results
        processing_time = time.time() - start_time
        batch_result = self._aggregate_results(results, processing_time)

        # Phase 4.4: LLM batch processing
        if with_llm and batch_result.successful > 0:
            logger.info("Starting LLM batch processing...")
            llm_result = self._process_llm_batch(
                batch_result.results,
                files,
                llm_model,
                risk_threshold,
            )
            batch_result.llm_result = llm_result
            batch_result.llm_enabled = True

            logger.info(
                f"LLM processing: {llm_result.processed_files} narratives "
                f"in {llm_result.processing_time_seconds:.2f}s"
            )

        logger.info(
            f"Batch processing complete: {batch_result.successful}/{batch_result.total_files} "
            f"successful in {processing_time:.2f}s"
        )

        return batch_result

    def _aggregate_results(
        self,
        results: List[BatchFileResult],
        processing_time: float,
    ) -> BatchAnalysisResult:
        """Aggregate individual file results into batch summary.

        Args:
            results: List of individual file results
            processing_time: Total processing time in seconds

        Returns:
            BatchAnalysisResult with aggregated statistics
        """
        successful_results = [r for r in results if r.success]
        failed_results = [r for r in results if not r.success]

        # Extract ForensicAnalysis objects
        analyses = [r.analysis for r in successful_results if r.analysis is not None]

        # Calculate aggregated risk score
        if analyses:
            risk_scores = self._calculate_risk_scores(analyses)
            aggregated_risk = sum(risk_scores) / len(risk_scores)
        else:
            aggregated_risk = 0.0

        # Risk distribution
        risk_dist = self._calculate_risk_distribution(analyses)

        return BatchAnalysisResult(
            total_files=len(results),
            successful=len(successful_results),
            failed=len(failed_results),
            results=analyses,
            failures=failed_results,
            aggregated_risk_score=aggregated_risk,
            risk_distribution=risk_dist,
            processing_time_seconds=processing_time,
        )

    def _calculate_risk_scores(self, analyses: List[ForensicAnalysis]) -> List[float]:
        """Convert RiskLevel enums to numeric scores for aggregation.

        Args:
            analyses: List of ForensicAnalysis results

        Returns:
            List of numeric risk scores (0.0-4.0)
        """
        risk_level_to_score = {
            RiskLevel.INFO: 0.0,
            RiskLevel.LOW: 1.0,
            RiskLevel.MEDIUM: 2.0,
            RiskLevel.HIGH: 3.0,
            RiskLevel.CRITICAL: 4.0,
        }

        return [
            risk_level_to_score.get(analysis.risk_assessment.overall_risk, 0.0)
            for analysis in analyses
        ]

    def _calculate_risk_distribution(
        self,
        analyses: List[ForensicAnalysis],
    ) -> Dict[str, int]:
        """Calculate distribution of files by risk level.

        Args:
            analyses: List of ForensicAnalysis results

        Returns:
            Dictionary mapping risk level names to counts
        """
        distribution: Dict[str, int] = {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        for analysis in analyses:
            level = analysis.risk_assessment.overall_risk.value
            if level in distribution:
                distribution[level] += 1

        return distribution

    def _process_llm_batch(
        self,
        analyses: List[ForensicAnalysis],
        file_paths: List[Path],
        llm_model: str,
        risk_threshold: float,
    ) -> Any:  # Returns BatchLLMResult
        """Process batch with LLM narrative generation.

        Args:
            analyses: List of ForensicAnalysis results
            file_paths: List of file paths
            llm_model: Model name for generation
            risk_threshold: Minimum risk score for processing

        Returns:
            BatchLLMResult with narratives
        """
        # Import here to avoid circular dependency
        from dwg_forensic.llm.batch_processor import BatchLLMProcessor

        # Progress tracking
        from tqdm import tqdm

        logger.info(
            f"Processing LLM narratives: model={llm_model}, "
            f"risk_threshold={risk_threshold}"
        )

        # Create processor
        processor = BatchLLMProcessor(model=llm_model)

        # Build file_paths list matching analyses order
        # Map successful analyses back to their original file paths
        analysis_paths = []
        for analysis in analyses:
            # Find matching file path by filename
            matching_path = next(
                (p for p in file_paths if p.name == analysis.file_info.filename),
                None
            )
            if matching_path:
                analysis_paths.append(matching_path)
            else:
                # Fallback: create Path from filename
                analysis_paths.append(Path(analysis.file_info.filename))

        # Process with progress bar
        with tqdm(
            total=len(analyses),
            desc="Processing LLM narratives",
            unit="file"
        ) as pbar:
            # Note: BatchLLMProcessor handles its own concurrency
            result = processor.process_batch(
                analyses,
                analysis_paths,
                risk_threshold,
            )

            # Update progress bar to completion
            pbar.update(len(analyses))

        return result


def process_batch(
    directory: Path,
    output_dir: Optional[Path] = None,
    num_workers: Optional[int] = None,
    recursive: bool = False,
    with_llm: bool = False,
    llm_model: str = "mistral",
    risk_threshold: float = 0.3,
) -> BatchAnalysisResult:
    """Convenience function to process a batch of DWG files.

    Args:
        directory: Directory containing DWG files
        output_dir: Optional directory for individual JSON reports
        num_workers: Number of parallel workers (default: CPU count)
        recursive: Whether to search subdirectories
        with_llm: Enable LLM narrative generation (requires Ollama)
        llm_model: Model name for LLM generation (default: "mistral")
        risk_threshold: Minimum risk score for LLM processing (default: 0.3)

    Returns:
        BatchAnalysisResult with aggregated results
    """
    processor = BatchProcessor(num_workers=num_workers)
    return processor.process_directory(
        directory=directory,
        output_dir=output_dir,
        recursive=recursive,
        with_llm=with_llm,
        llm_model=llm_model,
        risk_threshold=risk_threshold,
    )
