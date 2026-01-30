"""
Batch LLM Processor - Optimize LLM processing for 100+ file batches.

Implements risk-based sampling and async inference pooling to process
large batches efficiently (target: 100 files in <60s).

Phase 4.4 Implementation
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

from dwg_forensic.llm.ollama_client import OllamaClient
from dwg_forensic.llm.forensic_narrator import ForensicNarrator
from dwg_forensic.models import ForensicAnalysis, RiskLevel

logger = logging.getLogger(__name__)


# Risk level to numeric score mapping
RISK_SCORES = {
    RiskLevel.INFO: 0.0,
    RiskLevel.LOW: 1.0,
    RiskLevel.MEDIUM: 2.0,
    RiskLevel.HIGH: 3.0,
    RiskLevel.CRITICAL: 4.0,
}


@dataclass
class BatchLLMResult:
    """Result of batch LLM processing.

    Attributes:
        narratives: Dictionary mapping file paths to LLM narratives
        total_files: Total number of files in batch
        processed_files: Number of files that received LLM processing
        skipped_files: Number of files skipped (below risk threshold)
        failed_files: Number of files where LLM processing failed
        processing_time_seconds: Total LLM processing time
        model_used: Ollama model used for generation
    """
    narratives: Dict[str, str] = field(default_factory=dict)
    total_files: int = 0
    processed_files: int = 0
    skipped_files: int = 0
    failed_files: int = 0
    processing_time_seconds: float = 0.0
    model_used: str = ""

    # Grouping statistics
    groups: Dict[str, List[str]] = field(default_factory=dict)


def _calculate_risk_score(analysis: ForensicAnalysis) -> float:
    """Convert RiskLevel to numeric score.

    Args:
        analysis: ForensicAnalysis result

    Returns:
        Numeric risk score (0.0-4.0)
    """
    return RISK_SCORES.get(analysis.risk_assessment.overall_risk, 0.0)


def _classify_file_type(analysis: ForensicAnalysis) -> str:
    """Classify file by authoring application for grouping.

    Args:
        analysis: ForensicAnalysis result

    Returns:
        File type classification (e.g., 'autocad', 'revit', 'bricscad')
    """
    # Check application fingerprint
    if analysis.application_fingerprint:
        return analysis.application_fingerprint.detected_application.lower()

    # Check Revit detection
    if analysis.revit_detection and analysis.revit_detection.get("is_revit", False):
        return "revit"

    # Default to autocad for DWG files
    return "autocad"


class BatchLLMProcessor:
    """Batch processor for LLM narrative generation.

    Optimizes processing of large batches (100+ files) by:
    1. Risk-based sampling - Only process high-risk files
    2. Async inference pooling - Max 5 concurrent Ollama requests
    3. File type grouping - Consistent prompts for similar files
    """

    DEFAULT_RISK_THRESHOLD = 0.3  # Skip files with risk < 0.3 (LOW risk)
    MAX_CONCURRENT_REQUESTS = 5   # Limit concurrent Ollama requests

    def __init__(
        self,
        ollama_client: Optional[OllamaClient] = None,
        model: str = "mistral",
        max_concurrent: int = MAX_CONCURRENT_REQUESTS,
    ):
        """Initialize batch LLM processor.

        Args:
            ollama_client: Ollama client (created if None)
            model: Model name for generation
            max_concurrent: Max concurrent Ollama requests
        """
        self.client = ollama_client or OllamaClient(model=model)
        self.model = model
        self.max_concurrent = max_concurrent
        self.narrator = ForensicNarrator(ollama_client=self.client)

        logger.info(
            f"BatchLLMProcessor initialized: model={model}, "
            f"max_concurrent={max_concurrent}"
        )

    def process_batch(
        self,
        analyses: List[ForensicAnalysis],
        file_paths: List[Path],
        risk_threshold: float = DEFAULT_RISK_THRESHOLD,
    ) -> BatchLLMResult:
        """Process batch with LLM narrative generation.

        Implements risk-based sampling and async inference pooling.

        Args:
            analyses: List of ForensicAnalysis results
            file_paths: List of corresponding file paths
            risk_threshold: Minimum risk score to process (default: 0.3)

        Returns:
            BatchLLMResult with narratives and statistics
        """
        import time
        start_time = time.time()

        if len(analyses) != len(file_paths):
            raise ValueError("analyses and file_paths must have same length")

        # Step 1: Risk-based filtering
        filtered_pairs = self._filter_by_risk(analyses, file_paths, risk_threshold)

        logger.info(
            f"Risk filtering: {len(filtered_pairs)}/{len(analyses)} files "
            f"above threshold {risk_threshold}"
        )

        # Step 2: Group by file type
        groups = self._group_by_type(filtered_pairs)

        logger.info(f"Grouped into {len(groups)} file types: {list(groups.keys())}")

        # Step 3: Async batch processing
        narratives = self._process_async(filtered_pairs)

        processing_time = time.time() - start_time

        # Build result
        result = BatchLLMResult(
            narratives=narratives,
            total_files=len(analyses),
            processed_files=len(narratives),
            skipped_files=len(analyses) - len(filtered_pairs),
            failed_files=len(filtered_pairs) - len(narratives),
            processing_time_seconds=processing_time,
            model_used=self.model,
            groups={k: [str(p) for _, p in v] for k, v in groups.items()},
        )

        # Calculate throughput
        throughput = (
            result.processed_files / processing_time
            if processing_time > 0
            else 0.0
        )

        logger.info(
            f"Batch LLM processing complete: {result.processed_files} narratives "
            f"in {processing_time:.2f}s "
            f"({throughput:.1f} files/sec)"
        )

        return result

    def _filter_by_risk(
        self,
        analyses: List[ForensicAnalysis],
        file_paths: List[Path],
        risk_threshold: float,
    ) -> List[tuple[ForensicAnalysis, Path]]:
        """Filter analyses by risk score.

        Args:
            analyses: List of ForensicAnalysis results
            file_paths: List of file paths
            risk_threshold: Minimum risk score (0.0-4.0)

        Returns:
            List of (analysis, path) tuples above threshold
        """
        filtered = []

        for analysis, path in zip(analyses, file_paths):
            risk_score = _calculate_risk_score(analysis)

            if risk_score >= risk_threshold:
                filtered.append((analysis, path))
                logger.debug(
                    f"Including {path.name}: risk={risk_score:.1f} "
                    f"({analysis.risk_assessment.overall_risk.value})"
                )
            else:
                logger.debug(
                    f"Skipping {path.name}: risk={risk_score:.1f} below threshold"
                )

        return filtered

    def _group_by_type(
        self,
        pairs: List[tuple[ForensicAnalysis, Path]],
    ) -> Dict[str, List[tuple[ForensicAnalysis, Path]]]:
        """Group files by type for consistent prompting.

        Args:
            pairs: List of (analysis, path) tuples

        Returns:
            Dictionary mapping file type to list of pairs
        """
        groups: Dict[str, List[tuple[ForensicAnalysis, Path]]] = {}

        for analysis, path in pairs:
            file_type = _classify_file_type(analysis)

            if file_type not in groups:
                groups[file_type] = []

            groups[file_type].append((analysis, path))

        return groups

    def _process_async(
        self,
        pairs: List[tuple[ForensicAnalysis, Path]],
    ) -> Dict[str, str]:
        """Process files with async inference pooling.

        Uses ThreadPoolExecutor to run concurrent Ollama requests.
        Limited to max_concurrent to avoid overwhelming Ollama.

        Args:
            pairs: List of (analysis, path) tuples to process

        Returns:
            Dictionary mapping file path strings to narratives
        """
        narratives: Dict[str, str] = {}

        if not pairs:
            return narratives

        # Check if Ollama is available
        if not self.client.is_available():
            logger.warning("Ollama not available - skipping LLM processing")
            return narratives

        # Use ThreadPoolExecutor for concurrent I/O (HTTP requests)
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            # Submit all tasks
            future_to_path = {
                executor.submit(self._generate_narrative, analysis): path
                for analysis, path in pairs
            }

            # Collect results as they complete
            from concurrent.futures import as_completed

            for future in as_completed(future_to_path):
                path = future_to_path[future]

                try:
                    narrative = future.result()
                    if narrative:
                        narratives[str(path)] = narrative
                        logger.debug(f"Generated narrative for {path.name}")
                    else:
                        logger.warning(f"Empty narrative for {path.name}")

                except Exception as e:
                    logger.error(f"Failed to generate narrative for {path.name}: {e}")

        return narratives

    def _generate_narrative(self, analysis: ForensicAnalysis) -> Optional[str]:
        """Generate LLM narrative for a single analysis.

        Args:
            analysis: ForensicAnalysis result

        Returns:
            Generated narrative or None if failed
        """
        try:
            narrative = self.narrator.generate_narrative(analysis)
            return narrative

        except Exception as e:
            logger.error(f"Narrative generation failed: {e}")
            return None


def process_batch_llm(
    analyses: List[ForensicAnalysis],
    file_paths: List[Path],
    risk_threshold: float = BatchLLMProcessor.DEFAULT_RISK_THRESHOLD,
    model: str = "mistral",
    max_concurrent: int = BatchLLMProcessor.MAX_CONCURRENT_REQUESTS,
) -> BatchLLMResult:
    """Convenience function for batch LLM processing.

    Args:
        analyses: List of ForensicAnalysis results
        file_paths: List of corresponding file paths
        risk_threshold: Minimum risk score to process (default: 0.3)
        model: Ollama model name
        max_concurrent: Max concurrent requests

    Returns:
        BatchLLMResult with narratives and statistics
    """
    processor = BatchLLMProcessor(model=model, max_concurrent=max_concurrent)
    return processor.process_batch(analyses, file_paths, risk_threshold)
