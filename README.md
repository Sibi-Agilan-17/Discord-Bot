# Discord-Bot

Usage:

```py
from bot import *

prechecks()  # Run this to make sure the discord & python versions are compatible
bot = Bot()
```

**Features:**

1. `refresh` and `stop` methods
2. Embed generation
3. User blacklisting 
4. Optional sharding
5. Logging


**Cogs:**  Add cogs in the directory ./cogs

**Database:** Currently not supported, uses a json file instead
              
Setup

```py
bot = Bot(
db={
  path: 'path/to/db/'
}
)
```

Let me know if any changes are needed :)
PRs are always welcome
         
