"""Allow the same CLI through ``python -m ccr``."""
from .cli import main

raise SystemExit(main())
