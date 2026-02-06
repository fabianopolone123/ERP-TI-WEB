import logging
import os
import requests

logger = logging.getLogger(__name__)

WAPI_TOKEN = os.getenv("WAPI_TOKEN", "").strip()
WAPI_INSTANCE = os.getenv("WAPI_INSTANCE", "").strip()
WAPI_BASE = os.getenv("WAPI_BASE_URL", "https://api.w-api.app/v1")
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


def send_whatsapp_message(destination: str, message: str, timeout: float = 10.0) -> dict:
    _require_config()
    to, dest_type = _normalize_destination(destination)
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
