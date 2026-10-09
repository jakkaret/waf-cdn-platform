import ast
import json
import os
import unittest

NOTEBOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "waf_gen3_colab.ipynb")


class ColabNotebookTests(unittest.TestCase):
    def test_every_code_cell_compiles(self):
        """A syntax error in one cell stops Run all in Colab; catch it here instead."""
        with open(NOTEBOOK, encoding="utf-8") as f:
            nb = json.load(f)
        for i, cell in enumerate(nb["cells"]):
            if cell["cell_type"] != "code":
                continue
            # IPython shell / magic lines are not Python
            src = "".join(l if not l.lstrip().startswith(("!", "%")) else "\n" for l in cell["source"])
            with self.subTest(cell=i, first_line=src.split("\n", 1)[0][:80]):
                ast.parse(src)


if __name__ == "__main__":
    unittest.main()
