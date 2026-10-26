import base64
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sklearn.metrics import accuracy_score, confusion_matrix

from src.graphs import live_graphs, normal_graphs, plot_confusion_matrix
from src.maps import create_map

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PLOTS_DIR = PROJECT_ROOT / "plots"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def get_template_environment():
    return Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(['html', 'xml'])
    )


def resolve_report_path(report_file):
    path = Path(report_file)
    if path.is_absolute():
        return path
    if path.parts and path.parts[0] == "..":
        return PROJECT_ROOT / Path(*path.parts[1:])
    return PROJECT_ROOT / path


def encode_image_base64(image_path):
    path = Path(image_path)
    if not path.exists():
        return ""
    with open(path, "rb") as image_file:
        encoded = base64.b64encode(image_file.read()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


def render_report(template_name, context, report_file):
    env = get_template_environment()
    template = env.get_template(template_name)
    html_content = template.render(**context)
    output_path = resolve_report_path(report_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")
    print(f"Report saved as {report_file}")


def generate_testing_report(y, predicted, report_file="reports/model_report.html"):
    cm = confusion_matrix(y, predicted, labels=['malicious', 'normal'])
    tn, fp, fn, tp = cm.ravel()

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = accuracy_score(y, predicted)

    matrix_plot_path = PLOTS_DIR / "confusion_matrix.png"
    plot_confusion_matrix(cm, labels=['malicious', 'normal'], filename=matrix_plot_path)

    context = {
        "tpr": f"{tpr:.2f}",
        "fpr": f"{fpr:.2f}",
        "accuracy": f"{accuracy:.2f}",
        "confusion_matrix_image": encode_image_base64(matrix_plot_path),
    }
    render_report("model_report.html", context, report_file)
    return accuracy


def generate_pcap_analysis_report(result, report_file="reports/pcap_analysis_report.html"):
    normal_graphs(result)

    top_flows = result['flow_analysis'][:5]
    ips = {flow['source_ip'] for flow in result['flow_analysis']}
    ips |= {flow['destination_ip'] for flow in result['flow_analysis']}
    map_locations = create_map(ips)

    has_ml = 'ml_analysis' in result
    context = {
        "flows": top_flows,
        "flow_json_items": [json.dumps(flow, indent=4) for flow in top_flows],
        "rule_analysis": result['rule_analysis'],
        "rule_analysis_json": json.dumps(result['rule_analysis'], indent=4),
        "ml_analysis": result.get('ml_analysis'),
        "ml_analysis_json": json.dumps(result['ml_analysis'], indent=4) if has_ml else None,
        "flow_plot": encode_image_base64(PLOTS_DIR / "flow_analysis.png"),
        "rule_plot": encode_image_base64(PLOTS_DIR / "rule_analysis.png"),
        "ml_plot": encode_image_base64(PLOTS_DIR / "ml_analysis.png") if has_ml else None,
        "map_image": encode_image_base64(PLOTS_DIR / "map.png"),
        "map_locations": map_locations,
        "map_locations_json": json.dumps(map_locations, indent=4),
    }
    render_report("pcap_analysis_report.html", context, report_file)


def generate_live_report(result, report_file="reports/live_analysis_report.html"):
    live_graphs(result)

    has_ml = 'ml_analysis' in result
    context = {
        "rule_breaks": result['rule_breaks'],
        "rule_breaks_json": json.dumps(result['rule_breaks'], indent=4),
        "ml_analysis": result.get('ml_analysis'),
        "ml_analysis_json": json.dumps(result['ml_analysis'], indent=4) if has_ml else None,
        "rule_plot": encode_image_base64(PLOTS_DIR / "rule_analysis.png"),
        "ml_plot": encode_image_base64(PLOTS_DIR / "ml_analysis.png") if has_ml else None,
    }
    render_report("live_analysis_report.html", context, report_file)

