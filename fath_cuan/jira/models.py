from __future__ import annotations

from pydantic import BaseModel, Field


class JiraIssue(BaseModel):
    key: str
    summary: str = ""
    status: str = ""
    issue_type: str = Field(default="", alias="issuetype")

    @classmethod
    def from_raw(cls, raw: dict[str, object]) -> JiraIssue:
        fields = raw.get("fields", {})
        if not isinstance(fields, dict):
            fields = {}
        return cls(
            key=str(raw.get("key", "")),
            summary=str(fields.get("summary", "")),
            status=str((fields.get("status") or {}).get("name", "")),
            issuetype=str((fields.get("issuetype") or {}).get("name", "")),
        )
