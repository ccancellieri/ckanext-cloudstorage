#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os.path
import mimetypes
import logging
import ast

from pylons import c
from pylons import config
from webob.exc import HTTPFound

from pylons.i18n import _
import paste.fileapp

from ckan.common import request, response
from ckan import logic, model
from ckan.lib import base, uploader
import ckan.lib.helpers as h


import ckanext.cloudstorage.storage as _storage


log = logging.getLogger(__name__)

storage = _storage.CloudStorage
is_proxy_download=storage.proxy_download.fget(storage)


TRANSITION = ast.literal_eval(config['ckanext.cloudstorage.transition'])

class StorageController(base.BaseController):

    def resource_download(self, id, resource_id, filename=None):
        if TRANSITION:
            try:
                # Your override logic here
                # If this part fails, catch the failure and fall back to the default method
                log.info("Transition enabled, downloading resource {} from bucket".format(resource_id))
                return self.resource_download_from_bucket(id, resource_id, filename)
            except HTTPFound as e:
                # This is the redirect exception; re-raise it to allow the redirect to proceed.
                raise e
            except Exception as e:  # Be more specific with your exception handling
                # Log the error or handle it as necessary
                log.warning("Transition enabled, attempting to download reource {} from the disk after failing from bucket: {}".format(resource_id,e))
                # Fall back to the default behavior
                return self.resource_download_from_disk(id, resource_id, filename)
        else:
            # If transition is not enabled, directly use the original method
            log.info("Transition disabled, downloading resource {} from bucket".format(resource_id))
            return self.resource_download_from_bucket(id, resource_id, filename)

    def resource_download_from_bucket(self, id, resource_id, filename=None):
        context = {
            'model': model,
            'session': model.Session,
            'user': c.user or c.author,
            'auth_user_obj': c.userobj
        }

        try:
            resource = logic.get_action('resource_show')(
                context,
                {
                    'id': resource_id
                }
            )
        except logic.NotFound:
            base.abort(404, _('Resource not found'))
        except logic.NotAuthorized:
            base.abort(401, _('Unauthorized to read resource {0}'.format(id)))

        # This isn't a file upload, so either redirect to the source
        # (if available) or error out.
        if resource.get('url_type') != 'upload':
            url = resource.get('url')
            if not url:
                base.abort(404, _('No download is available'))
            h.redirect_to(url)

        if filename is None:
            # No filename was provided so we'll try to get one from the url.
            filename = os.path.basename(resource['url'])

        upload = uploader.get_resource_uploader(resource)

        # if the client requests with a Content-Type header (e.g. Text preview)
        # we have to add the header to the signature
        try:
            content_type = getattr(request, "content_type", None)
        except AttributeError:
            content_type = None
        
        # If the repository is private you may want to use ckan accout to proxy
        # protected contents
        # ckanext.cloudstorage.proxy_download = [False|True]
        # Default: False
        if is_proxy_download:
            # remote object
            obj = upload.get_object(resource['id'],filename)
            # metaadta
            extra = obj.extra
            if extra:
                # let's leverage on external mimetype if present
                response.headers['Content-Type'] = extra.get('content_type',content_type)
            # return stream back
            return upload.get_object_as_stream(obj)

        uploaded_url = upload.get_url_from_filename(resource['id'], filename,
                                                            content_type=content_type)
        
        # The uploaded file is missing for some reason, such as the
        # provider being down.
        if uploaded_url is None:
            base.abort(404, _('No download is available'))

        h.redirect_to(uploaded_url)

    def resource_download_from_disk(self, id, resource_id, filename=None):
        """
        Provides a direct download by either redirecting the user to the url
        stored or downloading an uploaded file directly.
        """
        context = {'model': model, 'session': model.Session,
                   'user': c.user, 'auth_user_obj': c.userobj}

        try:
            rsc = logic.get_action('resource_show')(context, {'id': resource_id})
            logic.get_action('package_show')(context, {'id': id})
        except (logic.NotFound, logic.NotAuthorized):
            base.abort(404, _('Resource not found'))

        if rsc.get('url_type') == 'upload':
            upload = uploader.get_resource_uploader(rsc)
            filepath = upload.get_path(rsc['id'])
            fileapp = paste.fileapp.FileApp(filepath)
            try:
                status, headers, app_iter = request.call_application(fileapp)
            except OSError:
                base.abort(404, _('Resource data not found'))
            response.headers.update(dict(headers))
            content_type, content_enc = mimetypes.guess_type(
                rsc.get('url', ''))
            if content_type:
                response.headers['Content-Type'] = content_type
            response.status = status
            return app_iter
        elif 'url' not in rsc:
            base.abort(404, _('No download is available'))
        h.redirect_to(rsc['url'])
