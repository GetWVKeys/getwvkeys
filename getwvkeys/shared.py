from dunamai import Version

from getwvkeys.libraries import Library
from getwvkeys.models.Shared import db

# get current git commit sha
website_version = Version.from_git().serialize(
    style=None, dirty=True, format="{base}-post.{distance}+{commit}.{dirty}.{branch}"
)

# create library instance
library = Library(db)
