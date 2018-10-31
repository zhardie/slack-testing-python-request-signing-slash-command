import os
import time
import hashlib
import hmac

from flask import abort, Flask, jsonify, request

from dotenv import load_dotenv
load_dotenv()

SIGNING_SECRET = os.environ["SIGNING_SECRET"]

app = Flask(__name__)


def handle(request):

    request_body = request.get_data().decode('utf-8')

    print(request_body)

    # request object is a dict with headers and body
    slack_timestamp = request.headers.get('X-Slack-Request-Timestamp')
    slack_signature = request.headers.get('X-Slack-Signature').encode()

    print('\nNEW REQUEST')

    if abs(time.time() - float(slack_timestamp)) > 60 * 5:
        print("Replay Attack")
        return

    base_string = 'v0:{}:{}'.format(
        slack_timestamp, request_body)

    my_signature = 'v0=' + hmac.new(
        bytes(SIGNING_SECRET, 'utf-8'),
        bytes(base_string, 'utf-8'),
        hashlib.sha256
    ).hexdigest()

    print(my_signature)
    print(slack_signature)

    if hmac.compare_digest(bytes(my_signature, 'utf-8'), slack_signature):
        print("Signature match")
        return True
    else:
        print("Signature did not match")
        return False


@app.route('/', methods=['GET'])
def test():

    return "hi"


@app.route('/hello-there', methods=['POST'])
def hello_there():

    if handle(request):
        return jsonify(
            response_type='in_channel',
            text='correct signature'
        )
    else:
        return jsonify(
            response_type='in_channel',
            text='wrong signature'
        )
    return


if __name__ == "__main__":
    app.run(debug=True)
