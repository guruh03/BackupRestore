## [2.1.4] - 2025-04-28

### PROJECT
- NETWORK ANALYTICS

### REPOSITORY
- Backend Repositories

### GROUPS
- Backup_Restore

### BRANCH
- main

### Features Added:
- The filename is being used to allow the user to initiate the backup for Postgres and ScyllaDB.

### Bug Fixes:
- Deletion - Summary - File List

### Modifications made:

- Summary has been renamed to admin_comment
- User comment and admin comments are taken up for further processing. 

### Upgrade Instructions:
- Ensure all related database migrations are applied after deploying this release.

- If you are using the main branch, make sure that all environment variables and configurations are updated to support HTTP with Authentication.