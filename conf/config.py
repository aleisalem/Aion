# Google Play Store Crawler Configuration
LANG            	= # can be en_US, fr_FR, ...
ANDROID_ID      	= # '38c6523ac43ef9e1'
GOOGLE_LOGIN    	= # 'someone@gmail.com'
GOOGLE_PASSWORD 	= # 'yourpassword'
AUTH_TOKEN      	= None
SEPARATOR       	= '|'

# Plotly API Key
PLOTLY_API		= # API Key or None

# Directories
AION_DIR 		= # 'some directory"
DOWNLOADS_DIR		= AION_DIR + "files/downloads"

# Logging and debug messages
VERBOSE			= "ON"
LOGGING			= "ON"
LOG_FILE		= AION_DIR + "/aion.log"
ADMIN_EMAIL		= # someone@somewhere.com

# Android SDK paths and constants
ANDROID_SDK 		= # 'some directory'
ANDROID_ADB 		= ANDROID_SDK + "/platform-tools/adb"

# Misc paths
GENYMOTION_PLAYER 	= '/opt/genymobile/genymotion/player'

# DB-related information
AION_DB			= AION_DIR + "/db/aion2.db"
HASHES_DB		= AION_DIR + "/db/hashes.db"
DB_RECOVERY		= AION_DIR + "/docs/dbrecovery2.sql"
