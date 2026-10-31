import re


_NIK_PATTERN = re.compile(r"(?<!\d)\d{16}(?!\d)")
_PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+62|08)(?:[\s.-]?\d){9,12}(?!\d)")


def mask_pribadi_data(text: str) -> str:
    """Mask Indonesian NIKs and mobile phone numbers in free text."""
    text = _NIK_PATTERN.sub("[REDACTED_NIK_UU_PDP]", text)
    return _PHONE_PATTERN.sub("[REDACTED_PHONE_UU_PDP]", text)