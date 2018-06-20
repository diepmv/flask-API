from app import create_app
from models import db

class InitialTests(TestCase):
	def setUp(self):
		self.app = create_app('test_config')
		self.test_client = self.app.test_client()

		self.app_context = self.app.app_context()
		self.app_context.push()

		self.test_user_name = "testuser"
		self.test_password = 'T3s!p4s5w0RDd12#'

		db.craete_all()

	def tearDown(self):
		self.session.remove()
		db.drop_all()
		self.app_context.pop()