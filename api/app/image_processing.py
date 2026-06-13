from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO

from PIL import Image, ImageOps, UnidentifiedImageError


@dataclass(frozen=True)
class ProcessedUpload:
    data: bytes
    content_type: str
    extension: str
    width: int | None
    height: int | None
    thumbnail_data: bytes | None
    thumbnail_content_type: str | None
    thumbnail_width: int | None
    thumbnail_height: int | None


FORMAT_BY_CONTENT_TYPE = {
    "image/jpeg": ("JPEG", "jpg"),
    "image/png": ("PNG", "png"),
    "image/webp": ("WEBP", "webp"),
}


def is_supported_image(content_type: str) -> bool:
    return content_type.lower().split(";")[0] in FORMAT_BY_CONTENT_TYPE


def encode_image(image: Image.Image, content_type: str) -> tuple[bytes, str]:
    normalized_type = content_type.lower().split(";")[0]
    image_format, extension = FORMAT_BY_CONTENT_TYPE.get(normalized_type, ("PNG", "png"))
    output = BytesIO()
    if image_format == "JPEG":
        if image.mode not in {"RGB", "L"}:
            image = image.convert("RGB")
        image.save(output, format=image_format, quality=88, optimize=True)
    elif image_format == "PNG":
        image.save(output, format=image_format, optimize=True)
    else:
        image.save(output, format=image_format, quality=88, method=6)
    return output.getvalue(), extension


def process_upload(
    original: bytes,
    content_type: str,
    extension: str,
    *,
    strip_metadata: bool,
    resize_image: bool,
    max_image_dimension: int,
    thumbnail_max_dimension: int,
) -> ProcessedUpload:
    normalized_type = content_type.lower().split(";")[0]
    if not is_supported_image(normalized_type):
        return ProcessedUpload(
            data=original,
            content_type=content_type,
            extension=extension,
            width=None,
            height=None,
            thumbnail_data=None,
            thumbnail_content_type=None,
            thumbnail_width=None,
            thumbnail_height=None,
        )

    try:
        with Image.open(BytesIO(original)) as opened:
            image = ImageOps.exif_transpose(opened)
            image.load()
    except (UnidentifiedImageError, OSError):
        return ProcessedUpload(
            data=original,
            content_type=content_type,
            extension=extension,
            width=None,
            height=None,
            thumbnail_data=None,
            thumbnail_content_type=None,
            thumbnail_width=None,
            thumbnail_height=None,
        )

    image_width, image_height = image.size
    stored_data = original
    stored_extension = extension
    if strip_metadata or resize_image:
        stored = image.copy()
        if resize_image:
            stored.thumbnail((max_image_dimension, max_image_dimension), Image.Resampling.LANCZOS)
        stored_data, stored_extension = encode_image(stored, normalized_type)
        image_width, image_height = stored.size

    thumbnail = image.copy()
    thumbnail.thumbnail((thumbnail_max_dimension, thumbnail_max_dimension), Image.Resampling.LANCZOS)
    thumbnail_bytes, _ = encode_image(thumbnail, "image/jpeg")
    return ProcessedUpload(
        data=stored_data,
        content_type=normalized_type,
        extension=stored_extension,
        width=image_width,
        height=image_height,
        thumbnail_data=thumbnail_bytes,
        thumbnail_content_type="image/jpeg",
        thumbnail_width=thumbnail.size[0],
        thumbnail_height=thumbnail.size[1],
    )

