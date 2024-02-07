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


## CKAN Organization Deletion and GCP Integration

The deletion of a CKAN organization triggers a specific sequence of actions within the integrated Google Cloud Platform (GCP) environment, focusing on the cleanup of workspace groups while preserving cloud storage resources.

### Workspace Group Deletion

- Upon the deletion of a CKAN organization, the associated GCP workspace group is automatically deleted. This action ensures that access to GCP resources tied to the organization is revoked, aligning with the organization's removal.
  - **Important Note:** The deletion targets only the GCP workspace group. This is a critical step in removing access control structures that are no longer necessary, reflecting the organization's cessation.

### Bucket Preservation

- Contrary to the workspace group, the Google Cloud Storage (GCS) bucket linked to the CKAN organization remains untouched. This policy is designed to prevent accidental data loss, ensuring that valuable organizational data stored in the bucket is not automatically deleted along with the organization.
  - **Data Management:** The preservation of the GCS bucket post-organization deletion necessitates manual intervention for data review or cleanup. It allows administrators to securely manage or migrate data according to their needs without the risk of immediate data erasure.

### Implications of Organization Deletion

This approach to handling the deletion of CKAN organizations within the GCP integration framework emphasizes data protection and cautious access management. By automatically removing the workspace group while retaining the storage bucket, it balances the need for security with the avoidance of unintended data loss. Administrators are thus encouraged to manually assess and manage the contents of the GCS bucket following an organization's deletion, ensuring data is handled appropriately.

The deletion protocol underscores the importance of deliberate data management practices, allowing for a controlled and secure closure of CKAN organizations within the cloud environment.

## GCP Integration with CKAN for Enhanced Metadata Management

This documentation details the integration between CKAN and Google Cloud Platform (GCP), specifically focusing on the creation of buckets and the metadata management of files uploaded within CKAN organizations.

### Metadata for Bucket Creation

Upon the establishment of a new CKAN organization, a dedicated bucket is automatically generated in GCP. This bucket is tagged with specific metadata attributes to ensure a clear linkage and management of organizational data. The metadata includes:

- `organization_id`: A unique identifier assigned to the CKAN organization.
- `organization_name`: The official name of the CKAN organization.
- `owner`: The email address of the sysadmin who initiated the creation of the organization.

This metadata is crucial for associating each bucket with its corresponding CKAN organization and the admin responsible, thereby simplifying the management process within GCP.

### Metadata for File Uploads

When a user uploads a file to a CKAN organization, and a related bucket is available, the file is stored with detailed metadata. This information not only contextualizes the file within the CKAN framework but also facilitates its lifecycle management. The metadata recorded with each file includes:

- `activate`: This boolean attribute indicates whether the file is active (true) or has been marked as deleted within CKAN (false). If a file is removed from CKAN and the setting `ckanext.cloudstorage.leave_files` is set to `true`, this flag will reflect the file's deactivation by switching to false.
- `organization_id`: Identifies the CKAN organization where the file is uploaded.
- `package_id`: The identifier for the specific package (dataset) the file is part of.
- `resource_id`: A unique identifier for the resource (file) itself.
- `owner`: The name or email of the user who uploaded the file.

This metadata schema is designed to ensure that each file's association with its respective organization, dataset, and uploader is meticulously recorded. Moreover, the inclusion of the `activate` field allows for nuanced file lifecycle management, accommodating scenarios where files are removed from CKAN but not necessarily from the storage backend, based on the configured preferences.

---

These guidelines aim to provide a clear understanding of the procedures and metadata considerations involved in managing data storage and organization through CKAN's integration with GCP.
