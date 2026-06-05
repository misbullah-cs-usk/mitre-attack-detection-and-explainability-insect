from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path

from ml_predict_then_llm_explain import (
    event_dict_to_text,
    predict_hierarchical,
    explain_with_llm
)

app = FastAPI(title="MITRE ATT&CK SOC Dashboard")

app.mount("/static", StaticFiles(directory="static"), name="static")


class EventInput(BaseModel):
    EventID: str = ""
    Image: str = ""
    CommandLine: str = ""
    ParentImage: str = ""
    ParentCommandLine: str = ""
    User: str = ""
    Computer: str = ""
    TargetFilename: str = ""
    TargetObject: str = ""
    Details: str = ""
    DestinationIp: str = ""
    DestinationPort: str = ""
    SourceIp: str = ""
    SourcePort: str = ""
    QueryName: str = ""
    CurrentDirectory: str = ""


@app.get("/")
def home():
    return {"message": "Open /static/index.html"}


@app.post("/api/analyze")
def analyze_event(event: EventInput):
    event_dict = event.model_dump()

    event_text = event_dict_to_text(event_dict)
    ml_prediction = predict_hierarchical(event_text)
    llm_result = explain_with_llm(event_text, ml_prediction)

    return {
        "event_text": event_text,
        "ml_prediction": ml_prediction,
        "llm_explanation": llm_result["llm_explanation"]
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}
