#!/usr/bin/env python
# -*- coding: utf-8 -*-
import cgi
import mimetypes
import magic
import os.path
import urlparse
from ast import literal_eval
from datetime import datetime, timedelta
from tempfile import SpooledTemporaryFile
import logging

from pylons import config
from pylons.i18n import _
from ckan import model
from ckan.lib import munge
import ckan.plugins as p
import ckan.model as model
from ckan.plugins import toolkit
import ckan.authz as authz
import ckan.logic as logic
from ckan.lib import base

from libcloud.storage.types import Provider, ObjectDoesNotExistError
from libcloud.storage.providers import get_driver

from werkzeug.datastructures import FileStorage as FlaskFileStorage

ALLOWED_UPLOAD_TYPES = (cgi.FieldStorage, FlaskFileStorage)

NotAuthorized = logic.NotAuthorized
MB = 1 << 20

log = logging.getLogger(__name__)

def _get_underlying_file(wrapper):
    if isinstance(wrapper, FlaskFileStorage):
        return wrapper.stream
    return wrapper.file

def _copy_file(input_file, output_file, max_size):
    input_file.seek(0)
    current_size = 0
    while True:
        current_size = current_size + 1
        # MB chunks
        data = input_file.read(MB)

        if not data:
            break
        output_file.write(data)
        if current_size > max_size:
            raise logic.ValidationError({'upload': ['File upload too large']})


class CloudStorage(object):
    def __init__(self):
        """
        Initialize the CloudStorage with a specific storage driver.
        """
        try:
            # Dynamically get the driver class from the Provider.
            driver_class = get_driver(getattr(Provider, self.driver_name))
            # Initialize the driver with the provided options.
            self.driver = driver_class(**self.driver_options)
        except AttributeError:
            raise ValueError("Invalid driver name: {}".format(self.driver_name))
        except Exception as e:
            raise ConnectionError("Failed to initialize driver: {}".format(e))

        self._container = None

    @property
    def container(self):
        """
        Return the currently configured libcloud container.
        """
        if self._container is None:
            self._container = self.driver.get_container(
                container_name=self.container_name
            )

        return self._container

    @property
    def driver_options(self):
        """
        A dictionary of options ckanext-cloudstorage has been configured to
        pass to the apache-libcloud driver.
        """
        return literal_eval(config['ckanext.cloudstorage.driver_options'])

    @property
    def driver_name(self):
        """
        The name of the driver (ex: AZURE_BLOBS, S3) that ckanext-cloudstorage
        is configured to use.


        .. note:: 

            This value is used to lookup the apache-libcloud driver to use
            based on the Provider enum.
        """
        return config['ckanext.cloudstorage.driver']
    
    @property
    def prefix(self):
        """
        The prefix of container or group name
        """
        return config['ckanext.cloudstorage.prefix']


    @property
    def domain(self):
        """
        gcp domain
        """
        return config['ckanext.cloudstorage.domain']

    @property
    def container_name(self):
        """
        The name of the container (also called buckets on some providers)
        ckanext-cloudstorage is configured to use.
        """
        return config['ckanext.cloudstorage.container_name']

    @container_name.setter
    def container_name(self, value):
        """
        Set the name of the container.
        """
        # Optional: Add validation or processing here
        self._container_name = value
        # Optional: Reset or update the container if necessary
        self._container = None

    @property
    def use_secure_urls(self):
        """
        `True` if ckanext-cloudstroage is configured to generate secure
        one-time URLs to resources, `False` otherwise.
        """
        return p.toolkit.asbool(
            config.get('ckanext.cloudstorage.use_secure_urls', False)
        )

    @property
    def leave_files(self):
        """
        `True` if ckanext-cloudstorage is configured to leave files on the
        provider instead of removing them when a resource/package is deleted,
        otherwise `False`.
        """
        return p.toolkit.asbool(
            config.get('ckanext.cloudstorage.leave_files', False)
        )


    @property
    def guess_mimetype(self):
        """
        `True` if ckanext-cloudstorage is configured to guess mime types,
        `False` otherwise.
        """
        return p.toolkit.asbool(
            config.get('ckanext.cloudstorage.guess_mimetype', False)
        )
        
    @property
    def transition(self):
        """
        `True` if ckanext-cloudstorage is configured to guess mime types,
        `False` otherwise.
        """
        return p.toolkit.asbool(
            config.get('ckanext.cloudstorage.transition', False)
        )

    @property
    def storage_path(self):
        """
        `True` if ckanext-cloudstorage is configured to guess mime types,
        `False` otherwise.
        """
        return config['ckan.storage_path']

    @property
    def proxy_download(self):
        """
        If the ckan may stream the object (will use service account to download
        from private storages)
        """
        return p.toolkit.asbool(
            config.get('ckanext.cloudstorage.proxy_download', False)
        )

    @property
    def can_use_advanced_google(self):
        """
        `True` if the `google-auth` module is installed and
        ckanext-cloudstorage has been configured to use Google, otherwise
        `False`.
        """
        # Are we even using GOOGLE?
        if self.driver_name == 'GOOGLE_STORAGE':
            try:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.driver_options["secret"]
                # Yes? Is the 'google-auth' package available?
                from google.auth import crypt
                assert crypt
                # check six >=1.5
                import six
                assert six.ensure_binary
                return True
            except ImportError:
                # fail fast
                # if we configure a google storage and we have secure_urls,
                # we may want to be sure to have it installed at runtime
                if self.use_secure_urls:
                    raise

        return False


class ResourceCloudStorage(CloudStorage):
    def __init__(self, resource):
            """
            Support for uploading resources to any storage provider
            implemented by the apache-libcloud library.

            :param resource: The resource dict.
            """
            log.info("Initializing ResourceCloudStorage with resource: %s", resource)
            super(ResourceCloudStorage, self).__init__()

            self.resource = resource
            self.filename = None
            self.old_filename = None
            self.file_upload = None
            self.mimetype = None

            self._initialize_storage_settings()
            self._handle_file_upload(resource)
            self._handle_clear_upload(resource)

    def _initialize_storage_settings(self):
        """
        Initialize storage settings from the resource.
        """
        self.role = str(self.get_user_role_in_organization()).encode('ascii', 'ignore')
        self.container_name = self.get_container_name_of_current_org()
        self.bucket_exist = self.check_bucket_exists(self.container_name)
        self.group_email = self.container_name + "@" + self.domain

    def _handle_file_upload(self, resource):
        """
        Handle the file upload process.
        """
        log.info("Handling file upload for resource: %s", resource)
        upload_field_storage = resource.pop('upload', None)
        multipart_name = resource.pop('multipart_name', None)

        if self.transition:
            if self.bucket_exist:
                if isinstance(upload_field_storage, (ALLOWED_UPLOAD_TYPES)):
                    self._process_file_upload(upload_field_storage, resource)
                elif multipart_name and self.can_use_advanced_aws:
                    self._process_multipart_upload(multipart_name, resource)
            else:
                self._process_file_upload_to_disk(upload_field_storage, resource)
        else:
            if isinstance(upload_field_storage, (ALLOWED_UPLOAD_TYPES)):
                self._process_file_upload(upload_field_storage, resource)
            elif multipart_name and self.can_use_advanced_aws:
                self._process_multipart_upload(multipart_name, resource)

    def _process_file_upload(self, upload_field_storage, resource):
        """
        Process a standard file upload.
        """
        log.info("Processing file upload: %s", upload_field_storage.filename)
        self.filename = munge.munge_filename(upload_field_storage.filename)
        self.file_upload = _get_underlying_file(upload_field_storage)
        resource['url'] = self.filename
        resource['url_type'] = 'upload'
        log.info("File uploaded successfully: %s", self.filename)

    def _process_file_upload_to_disk(self, upload_field_storage, resource):
        """
        Process a standard file upload to disk.
        """
        from ckan.common import config
        
        config_mimetype_guess = config.get('ckan.mimetype_guess', 'file_ext')
        
        log.info("Processing file upload: %s", upload_field_storage.filename)

        if config_mimetype_guess == 'file_ext':
            url = resource.get('url')
            self.mimetype = mimetypes.guess_type(url)[0]

        if isinstance(upload_field_storage, ALLOWED_UPLOAD_TYPES):
            self.filesize = 0  # bytes

            self.filename = upload_field_storage.filename
            self.filename = munge.munge_filename(self.filename)
            resource['url'] = self.filename
            resource['url_type'] = 'upload'
            resource['last_modified'] = datetime.utcnow()
            self.file_upload = _get_underlying_file(upload_field_storage)
            self.file_upload.seek(0, os.SEEK_END)
            self.filesize = self.file_upload.tell()
            # go back to the beginning of the file buffer
            self.file_upload.seek(0, os.SEEK_SET)

            # check if the mimetype failed from guessing with the url
            if not self.mimetype and config_mimetype_guess == 'file_ext':
                self.mimetype = mimetypes.guess_type(self.filename)[0]

            if not self.mimetype and config_mimetype_guess == 'file_contents':
                try:
                    self.mimetype = magic.from_buffer(self.file_upload.read(),
                                                      mime=True)
                    self.file_upload.seek(0, os.SEEK_SET)
                except IOError as e:
                    # Not that important if call above fails
                    self.mimetype = None

    def _process_multipart_upload(self, multipart_name, resource):
        """
        Process a multipart upload, specifically for AWS.
        """
        resource['url'] = munge.munge_filename(multipart_name)
        resource['url_type'] = 'upload'

    def _handle_clear_upload(self, resource):
        """
        Handle clearing of an upload.
        """
        self._clear = resource.pop('clear_upload', None)
        if self._clear and resource.get('id'):
            self._clear_old_upload(resource)

    def _clear_old_upload(self, resource):
        """
        Clear an old upload when a new file is uploaded.
        """
        old_resource = model.Session.query(model.Resource).get(resource['id'])
        self.old_filename = old_resource.url
        resource['url_type'] = ''

    @property
    def container_name(self):
        """
        Overridden container_name property.
        """
        return self._container_name

    @container_name.setter
    def container_name(self, value):
        """
        Overridden setter for container_name.
        """
        self._container_name = value

    def path_from_filename(self, rid, filename):
        """
        Returns a bucket path for the given resource_id and filename.

        :param rid: The resource ID.
        :param filename: The unmunged resource filename.
        """
        return os.path.join(
            'packages',
            self.package.id,
            'resources',
            rid,
            munge.munge_filename(filename)
        )

    def check_bucket_exists(self, bucket_name):
        """Check if a GCP bucket exists.

        Args:
            bucket_name (str): The name of the bucket to check.

        Returns:
            bool: True if the bucket exists, False otherwise.
        """
        from google.cloud import storage
        from google.cloud.exceptions import NotFound

        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.driver_options["secret"]

        storage_client = storage.Client()
        try:
            storage_client.get_bucket(bucket_name)
            log.info("Bucket {} exists".format(bucket_name))
            return True
        except NotFound as e:
            log.warning("Bucket {} does not exist: {}".format(bucket_name, e))
            return False
        except Exception as e:
            log.error("An error occurred: {}".format(e))
            return False

    def get_container_name_of_current_org(self):
        """
        Generates the container name for the current organization.

        It retrieves the organization from the database using the package's
        owner organization ID and constructs a container name using a predefined
        prefix and the organization's name.

        :return: A string representing the container name.
        """
        log.info("Retrieving container name for current organization")
        owner_org = str(self.package.owner_org).encode('ascii', 'ignore')
        org = model.Session.query(model.Group) \
            .filter(model.Group.id == owner_org).first()

        name = self.prefix + str(org.name).encode('ascii', 'ignore')
        log.info("Container name retrieved: %s", name)
        return name

    def get_user_role_in_organization(self):
        """
        Determines the user's role in the current organization.

        This method retrieves the role of the currently logged-in user in the
        organization that owns the package. It checks the user's membership in
        the organization and returns their role if found.

        :return: A string representing the user's role in the organization, or
                None if the user has no role or is not found.
        """
        org_id = str(self.package.owner_org).encode('ascii', 'ignore')
        user_name = toolkit.c.user
        user_id = authz.get_user_id_for_username(user_name, allow_none=True)
        if not user_id:
            return None
        # get any roles the user has for the group
        q = model.Session.query(model.Member) \
            .filter(model.Member.table_name == 'user') \
            .filter(model.Member.group_id == org_id) \
            .filter(model.Member.state == 'active') \
            .filter(model.Member.table_id == user_id)
        # return the first role we find
        for row in q.all():
            return row.capacity
        return None

    def upload(self, id, max_size=10):
        """
        Complete the file upload, or clear an existing upload.

        :param id: The resource_id.
        :param max_size: Ignored.
        """
        if self.filename:
            self._upload_file(id)
        elif self._clear and self.old_filename and not self.leave_files:
            self._delete_old_file(id)

    def _upload_file(self, id):
        """
        Handles the file uploading process.

        :param id: The resource_id.
        """
        if self.transition:
            if self.bucket_exist:
                self._upload_to_libcloud(id)
            else:
                self._upload_to_disk(id)
        else:
            self._upload_to_libcloud(id)

    def _upload_to_disk(self, id, max_size=10):
        '''Actually upload the file.

        :returns: ``'file uploaded'`` if a new file was successfully uploaded
            (whether it overwrote a previously uploaded file or not),
            ``'file deleted'`` if an existing uploaded file was deleted,
            or ``None`` if nothing changed
        :rtype: ``string`` or ``None``

        '''
        if not self.storage_path:
            return

        # Get directory and filepath on the system
        # where the file for this resource will be stored
        directory = self.get_directory(id)
        filepath = self.get_path(id)

        # If a filename has been provided (a file is being uploaded)
        # we write it to the filepath (and overwrite it if it already
        # exists). This way the uploaded file will always be stored
        # in the same location
        if self.filename:
            try:
                os.makedirs(directory)
            except OSError as e:
                # errno 17 is file already exists
                if e.errno != 17:
                    raise
            tmp_filepath = filepath + '~'
            with open(tmp_filepath, 'wb+') as output_file:
                try:
                    _copy_file(self.file_upload, output_file, max_size)
                except logic.ValidationError:
                    os.remove(tmp_filepath)
                    raise
                finally:
                    self.file_upload.close()
            os.rename(tmp_filepath, filepath)
            return

    def _upload_to_libcloud(self, id):
        """
        Uploads a file using the libcloud driver to the configured storage.

        This method handles the file upload process for various cloud storage
        services using the libcloud driver. It supports 'SpooledTemporaryFile' 
        for handling file uploads and streams the file to the designated 
        container and object name based on the resource ID and filename.

        :param id: The resource_id associated with the file to be uploaded.
        """
        # Specific handling for SpooledTemporaryFile
        if isinstance(self.file_upload, SpooledTemporaryFile):
            self.file_upload.next = self.file_upload.next()

        try:
            self.container.upload_object_via_stream(
                self.file_upload,
                object_name=self.path_from_filename(id, self.filename)
            )
        except Exception as e:
            log.error(e)
            base.abort(404, _('Bucket {} not found'.format(self.container_name)))

    def _delete_old_file(self, id):
        """
        Deletes an old file when a new file is uploaded.

        This method is invoked when a previously uploaded file is replaced
        by a new file or a link. It attempts to delete the old file from
        the storage container. If the file does not exist or has already
        been deleted, the method will silently complete without errors.

        :param id: The resource_id associated with the file to be deleted.
        """
        # This is only set when a previously-uploaded file is replace
        # by a link. We want to delete the previously-uploaded file.
        log.info("Deleting old file: %s", self.old_filename)
        try:
            self.container.delete_object(
                self.container.get_object(
                    self.path_from_filename(id, self.old_filename)
                )
            )
            log.info("Old file deleted: %s", self.old_filename)
        except ObjectDoesNotExistError:
            # It's possible for the object to have already been deleted, or
            # for it to not yet exist in a committed state due to an
            # outstanding lease.
            return

    def _generate_public_google_url(self, obj, user_obj, user_email):
        """
        Generates a signed URL for public Google Cloud Storage objects.

        For anonymous users, uses a service account to impersonate a group.
        For authenticated users with admin or editor roles, grants direct access.

        :param obj: The GCS object for which to generate the URL.
        :param user_obj: The user object of the currently logged-in user.
        :param user_email: The email address of the user.
        :return: A signed URL string.
        """
        import ckanext.cloudstorage.google_storage as storage

        if user_obj is None:
            # Use service account for anonymous users
            return storage.generate_signed_url_with_impersonated_user(
                self.driver_options['secret'],
                self.container_name,
                object_name=obj.name,
                impersonate_user=self.group_email,
                expiration=3600
            )
        else:
            if self.role in ("admin", "editor"):
                # Direct signed URL for admin and editor
                return storage.generate_signed_url(
                    self.driver_options['secret'],
                    self.container_name,
                    object_name=obj.name,
                    expiration=3600
                )
            else:
                # Impersonate a user for other roles
                return storage.generate_signed_url_with_impersonated_user(
                    self.driver_options['secret'],
                    self.container_name,
                    object_name=obj.name,
                    impersonate_user=user_email,
                    expiration=3600
                )

    def _generate_private_google_url(self, obj, user_role, user_email):
        """
        Generates a signed URL for private Google Cloud Storage objects.

        Access is based on the user's role. Admin and editor roles are given
        direct access, while member roles are handled through impersonation.

        :param obj: The GCS object for which to generate the URL.
        :param user_role: The role of the user in the organization.
        :param user_email: The email address of the user.
        :return: A signed URL string.
        """
        import ckanext.cloudstorage.google_storage as storage

        if user_role in ("admin", "editor"):
            # Direct signed URL for admin and editor
            return storage.generate_signed_url(
                self.driver_options['secret'],
                self.container_name,
                object_name=obj.name,
                expiration=3600
            )
        elif user_role == "member":
            # Impersonate a user for member role
            return storage.generate_signed_url_with_impersonated_user(
                self.driver_options['secret'],
                self.container_name,
                object_name=obj.name,
                impersonate_user=user_email,
                expiration=3600
            )
        else:
            raise NotAuthorized("User not authorized to read or download this file")

    def _generate_google_url(self, path):
        """
        Generates a signed URL for a Google Cloud Storage object.

        This method creates a signed URL for a GCS object, considering the
        package's privacy status and the user's role. For public packages, it
        either uses a service account for anonymous users or grants direct access
        for admin/editor roles. For private packages, access is based on user roles.
        The URL expires in 1 hour.

        :param path: The path to the object in the GCS bucket.
        :return: A signed URL for the GCS object. Raises NotAuthorized for
                unauthorized users.
        """
        import ckanext.cloudstorage.google_storage as storage

        obj=self.container.get_object(path)
        user_name = toolkit.c.user
        user_obj = toolkit.c.userobj

        is_private_package = self.package.is_private
        user_role = self.role
        user_email = str(user_obj.email).encode('ascii', 'ignore') if user_obj else None

        # For public packages
        if not is_private_package:
           return self._generate_public_google_url(obj,user_obj,user_email)
        # For private packages
        else:
            return self._generate_private_google_url(obj,user_role, user_email)

    def _generate_default_url(self, path):
        """
        Generate a default URL for storage providers that do not require special handling.

        :param path: The path of the object in the storage.
        :returns: A URL for the object or None if not applicable.
        """

        # Find the object for the given key.
        obj = self.container.get_object(path)
        if obj is None:
            return

        try:
            # Attempt to use the provider's CDN URL generation method
            return self.driver.get_object_cdn_url(obj)
        except NotImplementedError:
            # Handle storage providers like S3 or Google Cloud using known URL patterns
            if 'S3' in self.driver_name or 'GOOGLE_STORAGE' in self.driver_name:
                return 'https://{host}/{container}/{path}'.format(
                    host=self.driver.connection.host,
                    container=self.container_name,
                    path=path
                )
            # If none of the above, return None or raise an appropriate exception
            else:
                return None  # or raise an appropriate exception

    def get_url_from_filename(self, rid, filename, content_type=None):
        """
        Retrieve a publically accessible URL for the given resource_id
        and filename.

        .. note::

            Works for Google storage.

        :param rid: The resource ID.
        :param filename: The resource filename.
        :param content_type: Optionally a Content-Type header.

        :returns: Externally accessible URL or None.
        """
        # Find the key the file *should* be stored at.
        path = self.path_from_filename(rid, filename)

        # If advanced azure features are enabled, generate a temporary
        # shared access link instead of simply redirecting to the file.
        if self.can_use_advanced_google and self.use_secure_urls:
            return self._generate_google_url(path)
        else:
            return self._generate_default_url(path)

    def get_object(self, rid, filename):
        # Find the key the file *should* be stored at.
        path = self.path_from_filename(rid, filename)
        # Find the object for the given key.
        return self.container.get_object(path)

    def get_object_as_stream(self, obj):
        return self.driver.download_object_as_stream(obj) 
        
    @property
    def package(self):
        return model.Package.get(self.resource['package_id'])

    def get_directory(self, id):
        directory = ""
        if "resources" in self.storage_path:
            directory = os.path.join(self.storage_path,
                                 id[0:3], id[3:6])
        else:
            storage_path = os.path.join(self.storage_path, "resources")
            directory = os.path.join(storage_path,
                                 id[0:3], id[3:6])
        return directory

    def get_path(self, id):
        directory = self.get_directory(id)
        filepath = os.path.join(directory, id[6:])
        return filepath
