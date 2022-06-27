from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, user_json):
        self.user_json = user_json

    # Sobreescribir get_id, es necesario si no se tiene la propiedad id
    def get_id(self):
        object_id = self.user_json.get('_id')
        return str(object_id)