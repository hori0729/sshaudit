import json
import os
import unittest

from sshaudit import report
from sshaudit.correlation import Engine

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIX, name)) as fh:
        return json.load(fh)


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.enum = load("enum_web_debian.json")
        cls.findings = Engine().correlate(cls.enum,
                                          generated_at="2026-08-30T12:00:00Z").to_dict()
        cls.md = report.render(cls.findings, enumeration=cls.enum)

    def test_has_core_sections(self):
        for heading in ("# sshaudit — web-prod-1", "## Resumen", "## Punto de entrada",
                        "## Rutas de escalada CONFIRMADAS",
                        "## Rutas potenciales y condiciones teóricas (NO verificadas)"):
            self.assertIn(heading, self.md)

    def test_confirmed_path_has_evidence_and_repro_and_remediation(self):
        block = self.md.split("## Rutas de escalada CONFIRMADAS", 1)[1]
        block = block.split("## Rutas potenciales", 1)[0]
        self.assertIn("CONFIRMADO", block)
        self.assertIn("**Evidencia:**", block)
        self.assertIn("uid=0(root)", block)
        self.assertIn("**Reproducción", block)
        self.assertIn("**Remediación:**", block)
        self.assertIn("Paso 1", block)
        self.assertIn("(alternativo)", block)  # more than one confirmed path

    def test_unverified_paths_labelled(self):
        block = self.md.split("(NO verificadas)", 1)[1]
        self.assertIn("NO VERIFICADO", block)
        self.assertIn("NO PROBADO", block)  # theoretical kernel CVEs
        self.assertIn("CVE-", block)

    def test_no_ansi_escape_codes(self):
        self.assertNotIn("\x1b[", self.md)

    def test_pivot_material_table(self):
        self.assertIn("movimiento lateral / pivoting", self.md)
        self.assertIn("readable-private-keys", self.md)

    def test_sensitive_data_warning(self):
        self.assertIn("no se suba a repositorios", self.md)


class EdgeCaseTests(unittest.TestCase):
    def test_clean_host(self):
        md = report.render(Engine().correlate(load("enum_clean_rhel.json")).to_dict())
        self.assertIn("no se detectó ninguna ruta a root", md)
        self.assertIn("_Ninguna.", md)

    def test_enumeration_errors_section(self):
        enum = load("enum_web_debian.json")
        enum["errors"] = [{"section": "capabilities", "message": "getcap missing"}]
        md = report.render(Engine().correlate(enum).to_dict(), enumeration=enum)
        self.assertIn("## Errores de enumeración", md)
        self.assertIn("getcap missing", md)

    def test_empty_findings_does_not_crash(self):
        md = report.render({})
        self.assertIn("# sshaudit", md)

    def test_enumerate_mode_note(self):
        enum = load("enum_web_debian.json")
        enum["mode"] = "enumerate"
        enum["validations"] = []
        md = report.render(Engine().correlate(enum).to_dict(), enumeration=enum)
        self.assertIn("enumerate", md)
        self.assertIn("_Ninguna. No se validó", md)


if __name__ == "__main__":
    unittest.main()
