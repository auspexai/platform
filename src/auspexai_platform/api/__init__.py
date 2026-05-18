"""API route modules.

One submodule per resource. Each module exposes a `router: APIRouter` that
`main.create_app()` mounts under `/api/v0/`.

Resources arrive milestone-by-milestone (see `main.create_app()` docstring).
M1 ships health only.
"""
