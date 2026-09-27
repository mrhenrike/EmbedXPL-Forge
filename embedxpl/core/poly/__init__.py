# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — PolyExploit Orchestrator.

Provides multi-language exploit execution capabilities:
  - :class:`~embedxpl.core.poly.compiler.CCompiler` — C/C++ compile + run
  - :class:`~embedxpl.core.poly.runner.PolyRunner`  — Ruby/Node/PHP/Bash/Perl execution
  - Combined :class:`PolyExploit` mixin for modules needing both

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

from embedxpl.core.poly.compiler import CCompiler
from embedxpl.core.poly.runner import PolyRunner


class PolyExploit(CCompiler, PolyRunner):
    """Combined C compiler + multi-language runner mixin.

    Mix this into any exploit module that needs to compile C source
    AND/OR run scripts in other languages::

        from embedxpl.core.poly import PolyExploit
        from embedxpl.core.http.http_client import HTTPClient
        from embedxpl.core.exploit import *

        class Exploit(PolyExploit, HTTPClient):
            _C_SOURCE = \"\"\"
            #include <stdio.h>
            int main(int argc, char **argv) {
                printf(\"target: %s\\n\", argv[1]);
                return 0;
            }
            \"\"\"

            def run(self):
                binary = self.compile_c(self._C_SOURCE)
                if binary:
                    output = self.exec_binary(binary, [str(self.target)])
                    print_success(output)

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.0.0
    """


__all__ = ["CCompiler", "PolyRunner", "PolyExploit"]
