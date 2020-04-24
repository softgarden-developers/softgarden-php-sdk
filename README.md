softgarden PHP SDK
==================

The [softgarden-cloud API](http://dev.softgarden.de/) is
a set of APIs that connect your app to the softgarden cloud ATS.

This repository contains the open source PHP SDK that allows you to
access softgarden cloud API from your PHP app. Except as otherwise noted,
the softgarden PHP SDK is licensed under the Apache Licence, Version 2.0
(http://www.apache.org/licenses/LICENSE-2.0.html).


Usage
-----

The minimal you'll need to
have is:

    require 'softgarden-php-sdk/src/Softgarden.php';

    $softgarden = new Softgarden(array(
      'appId'  => 'YOUR_APP_ID',
      'secret' => 'YOUR_APP_SECRET' // only required if your app has an secret
    ));

    // call an API endpoint
    $response = $softgarden->get('v2/frontend/me');

To make [API][API] calls, the general pattern is:

      try {
        // make the api call, generic
        $response = $softgarden->api('v2/frontend/me');

        // make the api call, get
        $response = $softgarden->get('v2/frontend/me', $optionalQueryParamsAsArray);

        // make the api call, post
        $response = $softgarden->post('v2/frontend/me', $optionalPostParamsAsArray);

        // make the api call, put
        $response = $softgarden->put('v2/frontend/me', $optionalPostParamsAsArray);

        // make the api call, delete
        $response = $softgarden->delete('v2/frontend/me', $optionalQueryParamsAsArray);

      } catch (SoftgardenApiException $e) {
        error_log($e);
      }
    }

[examples]: http://github.com/softgarden/softgarden-php-sdk/blob/master/examples/example.php
[API]: http://dev.softgarden.de


Tests
-----

Currently, there is no test coverage, as we just started to develop this sdk.


Contributing
===========
Currently, there is no way to externally copntribute to our sdk.


Report Issues/Bugs
===============
[Bugs](https://dev.softgarden.de)

[Questions](http://dev.softgarden.de)
