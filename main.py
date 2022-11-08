import os
import time
from urllib.parse import urljoin

import requests as rest_client
from fastapi import APIRouter
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.status import HTTP_400_BAD_REQUEST

OAUTH2_ENDPOINT_BASE_DOMAIN = "https://example.com/"
APP_ID = os.environ.get("APP_ID", None)
APP_SECRET = os.environ.get("APP_SECRET", None)
REDIRECT_URI = os.environ.get("REDIRECT_URI", None)

router = APIRouter()

# 用户登录入口
@router.get("/login", tags=["authentication"])
async def login():
    unique_state_hash = int(round(time.time() * 1000))
    # 构造授权 URL，请根据开发者文档中的授权 URL 构造规则进行构造
    url = f"{OAUTH2_ENDPOINT_BASE_DOMAIN}cas/oauth2.0/authorize?client_id={APP_ID}&redirect_uri={REDIRECT_URI}&response_type=code&state={unique_state_hash}"
    return RedirectResponse(url=url)

# 回调 URL
@router.get("/oauth2/callback", tags=["authentication"])
async def callback(request: Request):
    code = request.query_params.get("code", None)
    # 用code换取access_token，请参考开发者文档中的“使用授权码换取令牌”部分
    res = rest_client.post(
        f"{OAUTH2_ENDPOINT_BASE_DOMAIN}cas/oauth2.0/token",
        data={
            "client_id": APP_ID,
            "client_secret": APP_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
        },
    )
    json_res = res.json()
    access_token = "access_token"
    if access_token not in json_res:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=f"OAuth2 failure")
    # 令牌 URL
    user_info_request = urljoin(
        OAUTH2_ENDPOINT_BASE_DOMAIN,
        f"cas/oauth2.0/profile?access_token={json_res.get(access_token,'')}",
    )
    # 返回用户信息
    user_res = rest_client.get(user_info_request)
    user_res_data = user_res.json()
    print(user_res_data)
    return user_res_data
