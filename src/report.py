from fpdf import FPDF
import json
from sklearn.metrics import accuracy_score, confusion_matrix

from src.graphs import plot_confusion_matrix, normal_graphs


def generate_testing_report(y,predicted, report_file="../reports/model_report.pdf"):
    cm = confusion_matrix(y, predicted, labels=['malicious', 'normal'])
    tn, fp, fn, tp = cm.ravel()

    # Metrics
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = accuracy_score(y, predicted)

    matrix_plot_filename = "../plots/confusion_matrix.png"

    plot_confusion_matrix(cm, labels=['malicious', 'normal'], filename=matrix_plot_filename)

    # Generate PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add title
    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(200, 10, txt="Model Evaluation Report", ln=True, align='C')
    pdf.ln(10)

    # Add metrics
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt=f"True Positive Rate (TPR): {tpr:.2f}", ln=True)
    pdf.cell(0, 10, txt=f"False Positive Rate (FPR): {fpr:.2f}", ln=True)
    pdf.cell(0, 10, txt=f"Accuracy: {accuracy:.2f}", ln=True)
    pdf.ln(10)

    # Add confusion matrix plot
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt="Confusion Matrix:", ln=True)
    pdf.ln(5)
    pdf.image(matrix_plot_filename, x=10, y=None, w=180)  # Insert the image into the PDF

    # Save the PDF
    pdf.output(report_file)
    print(f"Report saved as {report_file}")
    return accuracy


def generate_pcap_analysis_report(result, report_file="../reports/pcap_analysis_report.pdf"):
    normal_graphs(result)
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Add title
    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(200, 10, txt="PCAP Analysis Report", ln=True, align='C')
    pdf.ln(10)

    # Add textual information
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt="Flow Analysis:", ln=True)
    pdf.set_font("Courier", size=10)
    for flow in result['flow_analysis'][:5]:
        pdf.multi_cell(0, 10, txt=json.dumps(flow, indent=4))
    pdf.ln(5)

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt="Rule Analysis:", ln=True)
    pdf.set_font("Courier", size=10)
    pdf.multi_cell(0, 10, txt=json.dumps(result['rule_analysis'], indent=4))
    pdf.ln(5)

    if 'ml_analysis' in result:
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, txt="ML Analysis:", ln=True)
        pdf.set_font("Courier", size=10)
        pdf.multi_cell(0, 10, txt=json.dumps(result['ml_analysis'], indent=4))
        pdf.ln(5)

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt="Graphs:", ln=True)
    pdf.ln(5)
    pdf.image("../plots/flow_analysis.png", x=10, y=None, w=180)
    pdf.ln(10)
    pdf.image("../plots/rule_analysis.png", x=10, y=None, w=180)
    if 'ml_analysis' in result:
        pdf.ln(10)
        pdf.image("../plots/ml_analysis.png", x=10, y=None, w=180)

    # Save the PDF
    pdf.output(report_file)
    print(f"Report saved as {report_file}")