import json
import sys
from typing import Optional

from filters.agent_self_filter import AgentSelfFilter
from normalizer.ecs_normalizer import EcsNormalizer
from normalizer.kernel_event import KernelEvent
from filters.system_noise_filter import SystemNoiseFilter

from enricher.proc_enricher import ProcEnricher
from detection.sigma_engine import SigmaEngine
from alerting.deduplicator import AlertDeduplicator
from alerting.correlator import AlertCorrelator

from output.dispatcher import OutputDispatcher
from output.stdout_dispatcher import StdoutDispatcher


class EventPipeline:
    def __init__(
        self,
        normalizer: EcsNormalizer,
        agent_self_filter: Optional[AgentSelfFilter] = None,
        system_noise_filter: Optional[SystemNoiseFilter] = None,
        proc_enricher: Optional[ProcEnricher] = None,
        sigma_engine: Optional[SigmaEngine] = None,
        alert_deduplicator: Optional[AlertDeduplicator] = None,
        alert_correlator: Optional[AlertCorrelator] = None,
        debug_drops: bool = False,
        output_dispatcher: Optional[OutputDispatcher] = None,
    ) -> None:
        self.normalizer = normalizer
        self.agent_self_filter = agent_self_filter
        self.system_noise_filter = system_noise_filter
        self.proc_enricher = proc_enricher
        self.sigma_engine = sigma_engine
        self.alert_deduplicator = alert_deduplicator
        self.alert_correlator = alert_correlator
        self.debug_drops = debug_drops
        self.output_dispatcher = output_dispatcher or StdoutDispatcher()

    def process(self, event: KernelEvent) -> None:
        if self.agent_self_filter is not None:
            decision = self.agent_self_filter.evaluate(event)

            if decision.drop:
                self._debug_drop("agent_self_filter", decision.reason)
                return

        try:
            ecs_doc = self.normalizer.from_kernel_event(event)
        except Exception as exc:
            print(f"[drop] eroare normalizare: {exc}", file=sys.stderr)
            return

        if ecs_doc is None:
            return

        if self.proc_enricher is not None:
            try:
                ecs_doc = self.proc_enricher.enrich(ecs_doc)
            except Exception as exc:
                print(f"[warn] eroare proc_enricher: {exc}", file=sys.stderr)

        if self.system_noise_filter is not None:
            decision = self.system_noise_filter.evaluate(ecs_doc)

            if decision.drop:
                self._debug_drop("system_noise_filter", decision.reason)
                return

        if self.sigma_engine is not None:
            try:
                ecs_doc = self.sigma_engine.evaluate(ecs_doc)
            except Exception as exc:
                print(f"[warn] eroare sigma_engine: {exc}", file=sys.stderr)

        if self.alert_deduplicator is not None:
            try:
                decision = self.alert_deduplicator.evaluate(ecs_doc)
                ecs_doc = decision.ecs_doc

                if decision.drop:
                    self._debug_drop("alert_deduplicator", decision.reason)
                    return
            except Exception as exc:
                print(f"[warn] eroare alert_deduplicator: {exc}", file=sys.stderr)

        if self.alert_correlator is not None:
            try:
                ecs_doc = self.alert_correlator.process(ecs_doc)

                if ecs_doc is None:
                    return
            except Exception as exc:
                print(f"[warn] eroare alert_correlator: {exc}", file=sys.stderr)

        '''
        print(
            json.dumps(
                ecs_doc,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            flush=True,
        )
        '''
        try:
            self.output_dispatcher.emit(ecs_doc)
        except Exception as exc:
            print(f"[warn] eroare output_dispatcher: {exc}", file=sys.stderr)


    def _debug_drop(self, filter_name: str, reason: Optional[str]) -> None:
        if not self.debug_drops:
            return

        print(
            f"[drop] {filter_name}: {reason}",
            file=sys.stderr,
        )