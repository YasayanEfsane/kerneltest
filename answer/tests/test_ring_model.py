from __future__ import annotations

from dataclasses import replace
import unittest

from answer.tools.model_ring import (
    ModelConfig,
    SlotState,
    TerminalActor,
    Ticket,
    initial_state,
    invariant_violation,
    reproduce_evidence_identity_collision,
    run_actions,
    search,
    successors,
)


class RingModelTests(unittest.TestCase):
    def test_defective_model_discovers_aba_double_completion(self) -> None:
        config = ModelConfig(fixed=False, generation_bits=1, max_irps=3, max_depth=18)
        result = search(config)
        self.assertIsNotNone(result.violation)
        self.assertIn("completed 2 times", result.violation or "")
        actions = [step.action for step in result.trace]
        self.assertIn("execute_cancel", actions)
        self.assertIn("normal_complete", actions)
        stale_steps = [step for step in result.trace if step.state.stale_cancel_hit]
        self.assertTrue(stale_steps, "counterexample must contain the stale-ticket collision")
        final = result.trace[-1].state
        self.assertEqual(final.completions[3], 2)

    def test_corrected_model_has_no_violation_within_declared_bound(self) -> None:
        config = ModelConfig(fixed=True, generation_bits=1, max_irps=3, max_depth=18)
        result = search(config)
        self.assertIsNone(result.violation)
        self.assertGreater(result.explored_states, 1)
        self.assertEqual(result.depth_bound, 18)

    def test_fixed_model_blocks_reuse_until_cancel_detaches(self) -> None:
        config = ModelConfig(fixed=True, max_irps=2)
        state = run_actions(config, ("reserve", "publish", "queue_cancel", "normal_complete"))
        enabled = {name for name, _ in successors(state, config)}
        self.assertNotIn("free_slot", enabled)
        self.assertIn("execute_cancel", enabled)

        # Normal completion already owns the terminal transition.  The cancel
        # actor detaches but cannot increment the count a second time.
        options = dict(successors(state, config))
        state = options["execute_cancel"]
        self.assertEqual(state.completions[1], 1)
        self.assertEqual(state.terminal_actor, TerminalActor.NORMAL)
        self.assertIn("free_slot", {name for name, _ in successors(state, config)})

    def test_generation_and_owner_fields_wrap_in_reduced_model(self) -> None:
        config = ModelConfig(fixed=True, generation_bits=1, owner_bits=1, max_irps=2)
        state = run_actions(
            config,
            (
                "reserve",
                "publish",
                "normal_complete",
                "free_slot",
                "reserve",
                "publish",
                "normal_complete",
                "free_slot",
            ),
        )
        self.assertEqual(state.generation, 0)

        state = run_actions(config, ("disconnect", "reconnect", "disconnect", "reconnect"))
        self.assertEqual(state.owner_id, 0)

    def test_full_identity_rejects_same_truncated_fields_after_reuse(self) -> None:
        config = ModelConfig(fixed=True)
        state = replace(
            initial_state(config),
            slot_state=SlotState.READY,
            generation=1,
            owner_id=0,
            slot_sequence=3,
            occupant=3,
            payload_published=True,
        )
        stale = Ticket(irp_id=1, slot_index=0, generation=1, owner_id=0, full_sequence=1)
        self.assertTrue(stale.truncated_match(state))
        self.assertFalse(stale.full_match(state))

    def test_exact_16_bit_evidence_replay(self) -> None:
        replay = reproduce_evidence_identity_collision()
        self.assertEqual(replay.reuse_count, 65_536)
        self.assertEqual(replay.new_generation, 0xFFFE)
        self.assertEqual(replay.new_owner_id, 0x2A)
        self.assertTrue(replay.truncated_match)
        self.assertFalse(replay.full_identity_match)

    def test_publication_invariant_detects_ready_without_payload(self) -> None:
        config = ModelConfig(fixed=False)
        invalid = replace(
            initial_state(config),
            slot_state=SlotState.READY,
            occupant=1,
            payload_published=False,
        )
        self.assertIn("payload", invariant_violation(invalid, config) or "")


if __name__ == "__main__":
    unittest.main()
