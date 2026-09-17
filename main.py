from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyHeader
import secrets
import uvicorn

app = FastAPI()

# Hardcoded credentials
USERNAME = "admin"
PASSWORD = "secret123"
API_KEY = "my-super-secret-api-key"

basic_auth = HTTPBasic()
api_key_header = APIKeyHeader(name="X-API-Key")


def authenticate_basic(
    credentials: HTTPBasicCredentials = Depends(basic_auth),
):
    valid_username = secrets.compare_digest(
        credentials.username,
        USERNAME,
    )
    valid_password = secrets.compare_digest(
        credentials.password,
        PASSWORD,
    )

    if not (valid_username and valid_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


def authenticate_api_key(
    api_key: str = Security(api_key_header),
):
    if not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(
            status_code=403,
            detail="Invalid API key",
        )

    return api_key


@app.get("/")
def root():
    return {"message": "FastAPI server is running"}


@app.get("/protected")
def protected(
    username: str = Depends(authenticate_basic),
    api_key: str = Depends(authenticate_api_key),
):
    return {
        "message": "Authentication successful",
        "user": username,
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
