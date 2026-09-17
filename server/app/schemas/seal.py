from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


SealProfile = Literal["personal", "department", "academic"]
OutputFormat = Literal["sidecar", "qr", "pdf_signature_page"]
SignatureAlgorithm = Literal["SM3-with-SM2", "ML-DSA-65"]


class SealResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="UUID 签章标识")
    digest_algorithm: Literal["SM3"] = Field(..., description="常量字符串 SM3")
    digest: str = Field(..., description="文件 SM3 32 字节，标准 Base64")
    signature_algorithm: SignatureAlgorithm = Field(..., description="签名算法")
    signature: str = Field(..., description="签名原始字节的标准 Base64")
    certificate: str = Field(..., description="签发者叶证书 DER 的标准 Base64")
    timestamp: str = Field(..., description="带 Z 的 RFC 3339 UTC 时间")
