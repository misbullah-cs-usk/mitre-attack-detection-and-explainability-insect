import joblib
import numpy as np

parent_model = joblib.load("models/tfidf_sgd_sequence_parent.joblib")
sub_model = joblib.load("models/tfidf_sgd_sequence_subtechnique.joblib")


def topk(model, text, k=5):
    proba = model.predict_proba([text])[0]
    classes = model.classes_
    idx = np.argsort(proba)[::-1][:k]

    return [
        {
            "label": str(classes[i]),
            "confidence": float(proba[i])
        }
        for i in idx
    ]


def get_parent(label):
    return label.split(".")[0]


def predict_sequence(sequence_events, threshold=0.60):
    sequence_text = " [EVENT] ".join(sequence_events)

    parent_top3 = topk(parent_model, sequence_text, k=3)
    sub_top5 = topk(sub_model, sequence_text, k=5)

    best_parent = parent_top3[0]
    best_sub = sub_top5[0]

    if (
        best_sub["confidence"] >= threshold
        and get_parent(best_sub["label"]) == best_parent["label"]
    ):
        final_label = best_sub["label"]
        final_level = "sub-technique"
        confidence = best_sub["confidence"]
    else:
        final_label = best_parent["label"]
        final_level = "parent-technique"
        confidence = best_parent["confidence"]

    return {
        "final_label": final_label,
        "final_level": final_level,
        "confidence": confidence,
        "parent_top3": parent_top3,
        "subtechnique_top5": sub_top5
    }


sample_sequence = [
    "EventID=1 Image=c:\\windows\\system32\\cmd.exe CommandLine=cmd.exe /c whoami",
    "EventID=1 Image=c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe CommandLine=powershell.exe -nop -enc abc",
    "EventID=3 Image=powershell.exe DestinationIp=<ip> DestinationPort=443",
]

print(predict_sequence(sample_sequence, threshold=0.60))
