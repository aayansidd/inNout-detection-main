"""Command line: ``python -m app`` (serve) or ``python -m app warm_cache``."""

import argparse
import asyncio
import sys

from .config import get_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app", description="AEGIS USB backend")
    parser.add_argument(
        "command", nargs="?", default="serve", choices=["serve", "warm_cache"],
        help="serve (default): run the API on AEGIS_PORT; warm_cache: pre-fill the intel cache",
    )
    args = parser.parse_args(argv)
    settings = get_settings()
    if args.command == "warm_cache":
        from .warm_cache import warm

        try:
            report = asyncio.run(warm(settings, settings.demo_drive_path))
        except RuntimeError as exc:
            print(f"warm_cache: {exc}", file=sys.stderr)
            return 1
        return 1 if report.errors else 0
    import uvicorn

    uvicorn.run("app.api.main:app", host="127.0.0.1", port=settings.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
