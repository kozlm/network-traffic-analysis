import click

from src.machine_learning_model import train_model, test_model, create_and_train_model


def analyze_pcap():
    file_name = click.prompt("Enter the path of pcap file", type=str)
    use_ml = click.confirm("ML analysis?")
    click.echo(f"Analysing file: {file_name}, ML analysis: {'Yes' if use_ml else 'No'}")
    # analyze


def listen_on_interface():
    interface_name = click.prompt("Enter the interface name", type=str)
    use_ml = click.confirm("ML analysis?")
    click.echo(f"Listening on the interface: {interface_name}, ML analysis: {'Yes' if use_ml else 'No'}")
    # listen


def create_new_model():
    malicious_pcap = click.prompt("Enter the path of pcap file with malicious training data")
    normal_pcap = click.prompt("Enter the path of pcap file with normal training data")
    click.echo(f"Creating new model using files: {malicious_pcap}, {normal_pcap}")
    create_and_train_model(malicious_pcap, normal_pcap)

def train_current_model():
    malicious_pcap = click.prompt("Enter the path of pcap file with malicious training data")
    normal_pcap = click.prompt("Enter the path of pcap file with normal training data")
    click.echo(f"Training model using files: {malicious_pcap}, {normal_pcap}")
    train_model(malicious_pcap, normal_pcap)

def test_current_model():
    malicious_pcap = click.prompt("Enter the path of pcap file with malicious testing data")
    normal_pcap = click.prompt("Enter the path of pcap file with normal testing data")
    click.echo(f"Testing model using files: {malicious_pcap}, {normal_pcap}")
    print(test_model(malicious_pcap, normal_pcap))


@click.command()
def main_menu():
    while True:
        click.echo("What do you want to do?")
        click.echo("1. Analyze pcap file")
        click.echo("2. Analyze network traffic on the interface")
        click.echo("3. Create new model")
        click.echo("4. Train current model")
        click.echo("5. Test your model")
        click.echo("6. Exit")

        choice = click.prompt("Choose one of the options", type=int)

        if choice == 1:
            analyze_pcap()
        elif choice == 2:
            listen_on_interface()
        elif choice == 3:
            create_new_model()
        elif choice == 4:
            train_current_model()
        elif choice == 5:
            test_current_model()
        elif choice == 6:
            click.echo("Bye!")
            break
        else:
            click.echo("Wrong input, try again.")


if __name__ == "__main__":
    main_menu()
