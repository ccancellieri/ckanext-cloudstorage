# How does `ckanext-cloudstorage` works?

## CKAN Organization Creation and GCP Integration

This document outlines the automated process involved in the creation of a CKAN organization and its integration with Google Cloud Platform (GCP) services, ensuring a seamless setup of cloud resources necessary for secure data management.

### Process Overview

When a new CKAN organization is established, several automated actions are triggered to configure associated cloud resources on GCP. These actions include:

1. **GCP Workspace Group Creation**
   - A GCP workspace group is automatically generated. Its name is derived from a predefined prefix combined with the CKAN organization's name.
   - **Example:** If the prefix is `fao-catalog-` and the CKAN organization name is `test`, the GCP workspace group name will be `fao-catalog-test`.

2. **Group Email Creation**
   - An email address for the group is created using the prefix, the organization name, and a specified domain configuration.
   - **Example:** With a prefix of `fao-catalog-`, a domain of `fao.org`, and the organization name `test`, the group email will be `fao-catalog-test@fao.org`.

3. **Google Cloud Storage (GCS) Bucket Creation**
   - A GCS bucket is created with the same name as the GCP workspace group to store the organization's data securely in the cloud.
   - **Example:** The bucket name will be `fao-catalog-test`.

4. **Permission Granting**
   - The GCP workspace group is granted read and list permissions (`roles/storage.objectViewer`) on the newly created GCS bucket, allowing organization members appropriate access to their data.

### Implementation Details

This process ensures that each CKAN organization is automatically equipped with a dedicated and secure infrastructure on Google Cloud Platform, facilitating efficient data management and collaboration.

### Permissions

The permission granted to the GCP workspace group for the GCS bucket is as follows:

```yaml
roles:
  - storage.objectViewer
```

### Adding Members to CKAN Organizations

When new members are introduced to an existing CKAN organization, their integration is seamlessly extended to include corresponding roles within the associated Google Groups. This automated mapping between CKAN roles and Google Cloud Platform (GCP) roles ensures that each member has the appropriate level of access and control over cloud resources. The role assignments are as follows:

- **CKAN Role: `sysadmin`**
  - These users are added to the GCP workspace group related to the CKAN organization with the GCP role of `OWNER`. This grants them full access to manage the organization's resources and settings within GCP.

- **CKAN Role: `admin`**
  - Users with this role are added to the GCP workspace group with the GCP role of `MANAGER`. This role allows them to perform administrative tasks within the workspace group without full ownership privileges.

- **CKAN Role: `editor`**
  - Users assigned the `editor` role in CKAN are added to the GCP workspace group as `MEMBERS`. This enables them to access and modify resources within the group's scope.

- **CKAN Role: `MEMBER`**
  - CKAN users who are designated as `MEMBER` receive the same GCP role of `MEMBER` within the workspace group, allowing for basic access to view resources.

#### Role Definitions and Access Levels

The integration between CKAN and GCP roles is designed to reflect the level of responsibility and access required by each user within the organization. Here is a brief overview of what each GCP role entails:

- **OWNER**: Full access to all resources and settings within the GCP workspace group. Can add or remove members and adjust their roles.
- **MANAGER**: Administrative access to manage resources and settings within a limited scope. Cannot alter the group's membership structure.
- **MEMBER**: Basic access to view and interact with resources within the GCP workspace group, without the ability to make administrative changes.

This structured role assignment ensures a secure and efficient management of cloud resources, aligned with each member's responsibilities within the CKAN organization.


### Uploading and Downloading Files in CKAN Organizations

Managing file uploads and downloads within CKAN organizations involves a conditional process based on the `transition` phase setting. This setting dictates where files are stored and how they are accessed, ensuring flexibility and reliability in data management.

#### Transition Phase Enabled

When the `transition` phase is enabled:

- **File Uploads:**
  - Files uploaded to a CKAN organization are stored in the Google Cloud Storage (GCS) bucket specifically linked to that organization. If the targeted bucket does not exist, files are temporarily stored on disk. 
  - **Example:** Uploading a file to the `test` organization will target the `fao-catalog-test` bucket for storage.

- **File Downloads:**
  - Files are downloaded from the GCS bucket associated with the CKAN organization if available. Should the `transition` phase be disabled at the time of download, or if the bucket is inaccessible, files are retrieved from disk storage.

#### Transition Phase Disabled

When the `transition` phase is disabled:

- **File Uploads:**
  - Attempting to upload files directly to the associated GCS bucket. If the bucket linked to the CKAN organization does not exist, the upload process will result in an error.
  - **Example:** Files uploaded to the `test` organization are expected to be stored in the `fao-catalog-test` bucket. Absence of this bucket will prevent file upload.

- **File Downloads:**
  - Files are attempted to be downloaded from the GCS bucket. If the bucket does not exist or is otherwise inaccessible, the download attempt will fail, indicating the need for the bucket's presence or accessibility for successful file retrieval.

### Understanding Transition Phases

The `transition` phase setting plays a crucial role in the file management process within CKAN organizations, dictating the primary storage location for files (either GCS bucket or disk) and the fallback mechanisms in place for both file uploads and downloads. This flexibility allows for robust data management strategies that can adapt to various infrastructure configurations and availability.


## CKAN Organization Updates and GCP Integration

Modifications within a CKAN organization, such as user role updates or removals, are reflected in corresponding changes within the associated Google Cloud Platform (GCP) workspace group. This ensures that access and permissions remain aligned with the organization's current configuration.

### User Removal

- When a user is removed from a CKAN organization, they are automatically removed from the corresponding GCP workspace group as well. This ensures that only current members of the CKAN organization have access to the related cloud resources.
  - **Example:** If a user is removed from the `test` organization, they will also be removed from the `fao-catalog-test` GCP workspace group, maintaining secure access control.

### Role Updates

- Updates to a user's role within a CKAN organization trigger an automatic adjustment of their role within the GCP workspace group. This alignment ensures that each user's level of access in GCP accurately reflects their responsibilities within the CKAN organization.
  - **Example:** If a user's role in the `test` organization is changed from `editor` to `admin`, their role in the `fao-catalog-test` GCP workspace group will be updated from `MEMBER` to `MANAGER`. This change grants them the appropriate permissions to manage resources within the GCP environment effectively.

### Synchronizing CKAN and GCP Roles

This synchronization between CKAN organization roles and GCP workspace group roles is crucial for maintaining a secure and efficient environment for managing organizational resources. It ensures that permissions are accurately represented across platforms, reflecting the current structure and roles within the CKAN organization.

By automatically updating GCP workspace group memberships and roles based on changes within the CKAN organization, organizations can manage their cloud resources with confidence, knowing that access is restricted to authorized users with appropriate roles.

