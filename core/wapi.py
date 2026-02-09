import logging
import os
import unicodedata

import requests

logger = logging.getLogger(__name__)

WAPI_TOKEN = os.getenv("WAPI_TOKEN", "").strip()
WAPI_INSTANCE = os.getenv("WAPI_INSTANCE", "").strip()
WAPI_BASE = os.getenv("WAPI_BASE_URL", "https://api.w-api.app/v1").rstrip("/")
WAPI_SEND_URL = f"{WAPI_BASE}/message/send-text?instanceId={WAPI_INSTANCE}"
SUCCESS_STATUSES = {"success", "sent", "ok", "queued"}


def _require_config() -> None:
    if not WAPI_TOKEN or not WAPI_INSTANCE:
        raise ValueError("WAPI_TOKEN/WAPI_INSTANCE nao configurados.")


def _normalize_destination(destination: str) -> tuple[str, str]:
    normalized = (destination or "").strip()
    if not normalized:
        raise ValueError("Destino da mensagem nao pode ficar vazio.")
    if normalized.lower().endswith("@g.us"):
        return normalized, "group"
    if normalized.lower().endswith("@c.us"):
        return normalized, "contact"
    digits = "".join(ch for ch in normalized if ch.isdigit())
    if not digits:
        raise ValueError("Destino invalido. Informe um numero ou JID valido.")
    return digits, "contact"


def _build_payload(destination: str, message: str) -> dict:
    return {
        "token": WAPI_TOKEN,
        "phone": destination,
        "message": message,
    }


def _normalize_response(result: dict) -> tuple[str | None, str | None]:
    return (
        result.get("status") or result.get("state"),
        result.get("messageId") or result.get("insertedId"),
    )


def _normalize_text(value: str) -> str:
    raw = (value or "").strip().lower()
    return unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode("ascii")


def _extract_payload(result):
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        for key in ("data", "result", "groups", "chats", "items"):
            value = result.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = _extract_payload(value)
                if nested:
                    return nested
    return []


def _extract_jid(value) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        serialized = value.get("_serialized")
        if isinstance(serialized, str):
            return serialized.strip()
        user = str(value.get("user", "")).strip()
        server = str(value.get("server", "")).strip()
        if user and server:
            return f"{user}@{server}"
    return ""


def _iter_groups(payload):
    stack = [payload]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
            continue
        if not isinstance(item, dict):
            continue

        jid = ""
        for jid_key in ("id", "jid", "chatId", "groupId", "phone"):
            jid = _extract_jid(item.get(jid_key))
            if jid:
                break

        name = ""
        for name_key in ("name", "subject", "groupName", "title", "pushName"):
            value = item.get(name_key)
            if isinstance(value, str) and value.strip():
                name = value.strip()
                break

        if jid.lower().endswith("@g.us"):
            yield {"jid": jid, "name": name or jid}

        stack.extend(item.values())


def list_whatsapp_groups(timeout: float = 10.0) -> list[dict[str, str]]:
    _require_config()
    headers = {"Authorization": f"Bearer {WAPI_TOKEN}"}
    endpoints = [
        f"{WAPI_BASE}/group/get-all-groups?instanceId={WAPI_INSTANCE}",
        f"{WAPI_BASE}/group/list?instanceId={WAPI_INSTANCE}",
        f"{WAPI_BASE}/group/get-groups?instanceId={WAPI_INSTANCE}",
        f"{WAPI_BASE}/group/fetch-all?instanceId={WAPI_INSTANCE}",
        f"{WAPI_BASE}/chat/list?instanceId={WAPI_INSTANCE}",
        f"{WAPI_BASE}/chat/all?instanceId={WAPI_INSTANCE}",
    ]

    last_error = None
    for url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            payload = _extract_payload(response.json())
            groups = list(_iter_groups(payload))
            if not groups:
                continue
            unique = {}
            for group in groups:
                unique[group["jid"]] = group["name"]
            return [
                {"jid": jid, "name": name}
                for jid, name in sorted(unique.items(), key=lambda item: item[1].lower())
            ]
        except Exception as exc:
            last_error = exc

    if last_error:
        raise last_error
    return []


def find_whatsapp_groups_by_name(group_name: str) -> list[dict[str, str]]:
    target = _normalize_text(group_name)
    if not target:
        return []

    groups = list_whatsapp_groups()
    exact = []
    partial = []
    for group in groups:
        normalized_name = _normalize_text(group["name"])
        if normalized_name == target:
            exact.append(group)
        elif target in normalized_name:
            partial.append(group)
    return exact + partial


def send_whatsapp_message(destination: str, message: str, timeout: float = 10.0) -> dict:
    _require_config()
    to, _dest_type = _normalize_destination(destination)
    payload = _build_payload(to, message)
    headers = {
        "Authorization": f"Bearer {WAPI_TOKEN}",
        "Content-Type": "application/json",
    }
    response = requests.post(WAPI_SEND_URL, headers=headers, json=payload, timeout=timeout)
    try:
        response.raise_for_status()
    except requests.RequestException:
        logger.exception("Erro ao enviar mensagem para %s via WAPI", to)
        raise

    result = response.json()
    status, message_id = _normalize_response(result)
    ok_result = status in SUCCESS_STATUSES or bool(message_id)
    if not ok_result:
        logger.warning("Resposta inesperada do WAPI (%s): %s", to, result)
        raise requests.RequestException(f"WAPI retornou status {status} para {to}")
    return result
