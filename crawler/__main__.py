"""Module entry point for ``python -m crawler``."""

from crawler.cli import app


def main() -> None:
    """Run the command-line application."""
    app()


if __name__ == "__main__":
    main()
