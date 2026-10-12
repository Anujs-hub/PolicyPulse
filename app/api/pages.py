"""Server-rendered HTML pages (data is loaded by JavaScript from the REST API)."""
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
router = APIRouter(include_in_schema=False)

_PAGES = {"/": ("dashboard.html", "dashboard"), "/simulator": ("simulator.html", "simulator"),
          "/policies": ("policies.html", "policies"), "/audit": ("audit.html", "audit")}


def _make(template: str, active: str):
    async def view(request: Request):
        return TEMPLATES.TemplateResponse(request, template, {"active": active})
    return view


for path, (tpl, active) in _PAGES.items():
    router.add_api_route(path, _make(tpl, active), methods=["GET"], name=active)
