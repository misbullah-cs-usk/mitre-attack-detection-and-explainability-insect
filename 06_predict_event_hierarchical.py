import joblib
import numpy as np


PARENT_MODEL = "models/tfidf_sgd_parent.joblib"
SUB_MODEL = "models/tfidf_sgd_subtechnique.joblib"

parent_model = joblib.load(PARENT_MODEL)
sub_model = joblib.load(SUB_MODEL)


def topk(model, text, k=5):
    proba = model.predict_proba([text])[0]
    classes = model.classes_

    idx = np.argsort(proba)[::-1][:k]

    return [
        {
            "label": classes[i],
            "confidence": float(proba[i])
        }
        for i in idx
    ]


def get_parent(tid):
    return tid.split(".")[0]


def predict_hierarchical(text, threshold=0.60):
    parent_top = topk(parent_model, text, k=3)
    sub_top = topk(sub_model, text, k=5)

    best_parent = parent_top[0]
    best_sub = sub_top[0]

    sub_parent = get_parent(best_sub["label"])

    # Conservative SOC decision logic
    if best_sub["confidence"] >= threshold and sub_parent == best_parent["label"]:
        final_label = best_sub["label"]
        final_level = "sub-technique"
    else:
        final_label = best_parent["label"]
        final_level = "parent-technique"

    return {
        "final_label": final_label,
        "final_level": final_level,
        "parent_top3": parent_top,
        "subtechnique_top5": sub_top
    }


sample_text = """
EventID=1
Image=c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe
CommandLine=powershell.exe -nop -w hidden -enc SQBFAFgA...
ParentImage=c:\\windows\\system32\\cmd.exe
ParentCommandLine=cmd.exe /c powershell.exe -enc SQBFAFgA...
User=corp\\alice
Computer=win10-01
"""

result = predict_hierarchical(sample_text, threshold=0.60)
print(result)
