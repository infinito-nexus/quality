from tests.integration.support import SECRET

SECRET_RULE = "security.secret"
BINARY_RULE = "security.binary-code"
DOCKERFILE_RULE = "coding.dockerfile"
SECRET_LINE = f'TOKEN = "{SECRET}"\n'
COMMIT_MESSAGE_CANARY = "QualityMessageCanary"
