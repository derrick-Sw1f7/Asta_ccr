"""Deterministic semantic slicing; exact character preservation is mandatory."""
from __future__ import annotations

import re

from .contracts import Event, Segment


# A paragraph delimiter includes blank lines and their horizontal whitespace.
# It is assigned to the preceding slice so concatenation exactly reconstructs
# the source; CRLF and LF are deliberately not normalized.
_NEWLINE = r"(?:\r\n|(?<!\r)\n|\r(?!\n))"
_BLANK_LINES = re.compile(rf"{_NEWLINE}[ \t]*{_NEWLINE}(?:[ \t]*{_NEWLINE})*")


def segment_events(events: tuple[Event, ...]) -> tuple[Segment, ...]:
    """Split message paragraphs; tool/security events stay atomic.

    A child retains the complete parent Event so a secret naming field in one
    paragraph can protect a value located in a different paragraph.
    """
    if type(events) not in (tuple, list):
        raise ValueError("segmentation requires an Event sequence")
    segments: list[Segment] = []
    seen: set[str] = set()
    for event in events:
        if not isinstance(event, Event) or type(event.content) is not str:
            raise ValueError("segmentation requires valid Event records")
        if type(event.event_id) is not str or not event.event_id.strip() or event.event_id in seen:
            raise ValueError("segmentation requires unique nonempty event IDs")
        seen.add(event.event_id)
        atomic = (
            event.kind != "message"
            or event.role == "tool"
            or event.outcome == "rejected"
            or event.retry_of is not None
            or event.tool_name is not None
            or any(tag != "none" for tag in event.safety_tags)
        )
        pieces: list[str] = []
        if atomic:
            pieces = [event.content]
        else:
            start = 0
            for match in _BLANK_LINES.finditer(event.content):
                pieces.append(event.content[start:match.end()])
                start = match.end()
            if start < len(event.content) or not pieces:
                pieces.append(event.content[start:])
        for index, content in enumerate(pieces):
            segments.append(Segment(
                segment_id=f"s{len(segments) + 1:06d}",
                event=event,
                index=index,
                content=content,
            ))
    return tuple(segments)
