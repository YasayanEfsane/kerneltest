from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RepositoryTests(unittest.TestCase):
    def test_required_reports_exist(self) -> None:
        required = [
            "README.md",
            "answer/04_ring_lifetime.md",
            "answer/05_deadlock.md",
            "answer/06_ocvm.md",
            "answer/07_integrity.md",
            "answer/08_root_cause_matrix.md",
            "answer/09_patch_design.md",
            "answer/10_validation_plan.md",
            "answer/final_report_tr.md",
            ".github/workflows/tests.yml",
        ]
        for relative in required:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file())

    def test_ioctl_document_matches_executable_decoder(self) -> None:
        report = (ROOT / "answer/03_ioctl_abi.md").read_text(encoding="utf-8")
        for value in ("0x901", "0x902", "0x903", "0x904"):
            self.assertIn(value, report)
        for obsolete in ("0x790", "0x792", "0x794", "0x796"):
            self.assertNotIn(obsolete, report)

    def test_gitignore_is_not_a_markdown_or_model_transcript(self) -> None:
        content = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertNotIn("```", content)
        self.assertNotIn("Expected Output", content)
        self.assertIn("__pycache__/", content)

    def test_python_sources_have_no_absolute_workspace_import(self) -> None:
        forbidden = "/" + "workspace/answer"
        for source in (ROOT / "answer").rglob("*.py"):
            with self.subTest(path=str(source.relative_to(ROOT))):
                self.assertNotIn(forbidden, source.read_text(encoding="utf-8"))

    def test_readme_states_evidence_boundary(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("synthetic evidence-capsule benchmark", readme)
        self.assertIn("no Windows driver", readme)


if __name__ == "__main__":
    unittest.main()
