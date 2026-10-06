"""PipelineGuard - CI/CD pipeline security auditor."""
__version__ = "1.2.0"

SUPPORT = {
    "name": "Dexel Software Solutions",
    "email": "dexelsoftwaresolutions@gmail.com",
    "github": "https://github.com/dexel-software-solutions",
    "issues": "https://github.com/dexel-software-solutions/pipelineguard/issues",
}


def support_text() -> str:
    return (f"{SUPPORT['name']}\n  Email : {SUPPORT['email']}\n"
            f"  GitHub: {SUPPORT['github']}\n  Issues: {SUPPORT['issues']}")
