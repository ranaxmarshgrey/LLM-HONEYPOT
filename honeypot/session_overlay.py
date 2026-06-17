"""Session-local write overlay for FakeFS (Sprint 3 fix).

Tracks files and directories an attacker "creates" during their session
so that ``mkdir foo && cd foo`` works convincingly. The overlay is an
in-memory dict that is discarded when the session ends — nothing touches
the persona JSON or the real filesystem.

Read operations (ls, cat, cd, find) merge overlay state with FakeFS,
respecting deletions. Write operations (mkdir, touch, rm, cp, mv,
echo > file) only modify the overlay.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from honeypot.fakefs import FakeFS


class OverlayEntry:
    """A single entry in the session overlay."""

    __slots__ = ("type", "content", "owner", "group", "permissions",
                 "created", "modified", "children")

    def __init__(
        self,
        entry_type: str,
        content: str = "",
        owner: str = "root",
        group: str = "root",
        permissions: str = "0644",
    ) -> None:
        self.type = entry_type
        self.content = content
        self.owner = owner
        self.group = group
        self.permissions = permissions
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.created = now
        self.modified = now
        self.children: List[str] = []


class SessionOverlay:
    """Per-session filesystem overlay on top of FakeFS.

    Tracks attacker-created files/directories and deletions.
    All state lives in memory and is discarded when the session ends.

    Args:
        default_owner: Default owner for newly created entries.
        default_group: Default group for newly created entries.
    """

    def __init__(
        self,
        default_owner: str = "root",
        default_group: str = "root",
    ) -> None:
        self._entries: Dict[str, OverlayEntry] = {}
        self._deleted: set[str] = set()
        self._default_owner = default_owner
        self._default_group = default_group

    @property
    def entries(self) -> Dict[str, OverlayEntry]:
        return self._entries

    @property
    def deleted_paths(self) -> set[str]:
        return self._deleted

    def mkdir(self, path: str, permissions: str = "0755") -> None:
        """Create a directory in the overlay.

        Also creates any missing parent directories.
        """
        self._deleted.discard(path)

        parts = path.strip("/").split("/")
        for i in range(1, len(parts)):
            parent = "/" + "/".join(parts[:i])
            if parent not in self._entries:
                self._entries[parent] = OverlayEntry(
                    "directory",
                    owner=self._default_owner,
                    group=self._default_group,
                    permissions="0755",
                )
            self._deleted.discard(parent)

        self._entries[path] = OverlayEntry(
            "directory",
            owner=self._default_owner,
            group=self._default_group,
            permissions=permissions,
        )

        parent_dir = path.rsplit("/", 1)[0] or "/"
        if parent_dir in self._entries:
            child_name = path.rsplit("/", 1)[-1]
            if child_name not in self._entries[parent_dir].children:
                self._entries[parent_dir].children.append(child_name)

    def touch(self, path: str, content: str = "") -> None:
        """Create or update a file in the overlay."""
        self._deleted.discard(path)
        if path in self._entries:
            self._entries[path].modified = datetime.now(
                tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            return

        self._entries[path] = OverlayEntry(
            "file",
            content=content,
            owner=self._default_owner,
            group=self._default_group,
        )

        parent_dir = path.rsplit("/", 1)[0] or "/"
        if parent_dir in self._entries:
            child_name = path.rsplit("/", 1)[-1]
            if child_name not in self._entries[parent_dir].children:
                self._entries[parent_dir].children.append(child_name)

    def write_file(self, path: str, content: str) -> None:
        """Create or overwrite a file with specific content."""
        self._deleted.discard(path)
        if path in self._entries:
            self._entries[path].content = content
            self._entries[path].modified = datetime.now(
                tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            self._entries[path] = OverlayEntry(
                "file",
                content=content,
                owner=self._default_owner,
                group=self._default_group,
            )
            parent_dir = path.rsplit("/", 1)[0] or "/"
            if parent_dir in self._entries:
                child_name = path.rsplit("/", 1)[-1]
                if child_name not in self._entries[parent_dir].children:
                    self._entries[parent_dir].children.append(child_name)

    def rm(self, path: str, recursive: bool = False) -> None:
        """Mark a path as deleted.

        If recursive, also deletes all children.
        """
        self._deleted.add(path)
        self._entries.pop(path, None)

        parent_dir = path.rsplit("/", 1)[0] or "/"
        child_name = path.rsplit("/", 1)[-1]
        if parent_dir in self._entries and child_name in self._entries[parent_dir].children:
            self._entries[parent_dir].children.remove(child_name)

        if recursive:
            prefix = path.rstrip("/") + "/"
            for p in list(self._entries.keys()):
                if p.startswith(prefix):
                    self._entries.pop(p)
                    self._deleted.add(p)

    def cp(self, src: str, dst: str, fakefs: FakeFS) -> None:
        """Copy a file from overlay or FakeFS into the overlay."""
        content = self.get_content(src, fakefs)
        if content is not None:
            self.write_file(dst, content)

    def mv(self, src: str, dst: str, fakefs: FakeFS) -> None:
        """Move a file/directory from overlay or FakeFS into overlay."""
        if src in self._entries:
            entry = self._entries.pop(src)
            self._entries[dst] = entry
            self._deleted.add(src)
        elif fakefs.path_exists(src):
            if fakefs.is_file(src):
                try:
                    content = fakefs.get_file_content(src)
                    self.write_file(dst, content)
                except (FileNotFoundError, PermissionError):
                    self.touch(dst)
            else:
                self.mkdir(dst)
            self._deleted.add(src)

    def exists(self, path: str, fakefs: FakeFS) -> bool:
        """Check if path exists in overlay or FakeFS (respecting deletions)."""
        if path in self._deleted:
            return False
        if path in self._entries:
            return True
        return fakefs.path_exists(path)

    def is_directory(self, path: str, fakefs: FakeFS) -> bool:
        """Check if path is a directory in overlay or FakeFS."""
        if path in self._deleted:
            return False
        if path in self._entries:
            return self._entries[path].type == "directory"
        return fakefs.is_directory(path)

    def is_file(self, path: str, fakefs: FakeFS) -> bool:
        """Check if path is a file in overlay or FakeFS."""
        if path in self._deleted:
            return False
        if path in self._entries:
            return self._entries[path].type == "file"
        return fakefs.is_file(path)

    def get_content(self, path: str, fakefs: FakeFS) -> Optional[str]:
        """Get file content from overlay first, then FakeFS."""
        if path in self._deleted:
            return None
        if path in self._entries:
            return self._entries[path].content
        try:
            return fakefs.get_file_content(path)
        except (FileNotFoundError, IsADirectoryError, PermissionError):
            return None

    def get_children(self, path: str) -> List[str]:
        """Get children of a directory from overlay only."""
        entry = self._entries.get(path)
        if entry is None or entry.type != "directory":
            return []
        return list(entry.children)

    def get_merged_children(self, path: str, fakefs: FakeFS) -> List[str]:
        """Merge overlay and FakeFS children, respecting deletions.

        Returns the combined list of child names for a directory,
        with overlay additions included and deleted items excluded.
        """
        children: set[str] = set()
        prefix = path.rstrip("/") + "/"

        fs_entry = fakefs.persona.filesystem.get(path)
        if fs_entry is not None and fs_entry.type == "directory" and fs_entry.children:
            for child in fs_entry.children:
                child_path = f"{path.rstrip('/')}/{child}"
                if child_path not in self._deleted:
                    children.add(child)

        if path in self._entries and self._entries[path].type == "directory":
            for child in self._entries[path].children:
                child_path = f"{path.rstrip('/')}/{child}"
                if child_path not in self._deleted:
                    children.add(child)

        for opath in self._entries:
            if opath.startswith(prefix) and opath not in self._deleted:
                remainder = opath[len(prefix):]
                if "/" not in remainder:
                    children.add(remainder)

        return sorted(children)

    def get_overlay_entry_for_listing(self, path: str) -> Optional[dict]:
        """Get overlay entry metadata formatted for ls -l display."""
        entry = self._entries.get(path)
        if entry is None:
            return None
        return {
            "type": entry.type,
            "owner": entry.owner,
            "group": entry.group,
            "permissions": entry.permissions,
            "modified": entry.modified,
            "size_bytes": len(entry.content) if entry.type == "file" else 4096,
        }
