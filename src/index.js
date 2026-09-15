const SHOPIFY_API_VERSION = '2026-07';

/* =========================================================
   RESPONSE HELPERS
========================================================= */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}


/* =========================================================
   ENVIRONMENT VALIDATION
========================================================= */

function validateEnvironment(env) {
  const required = [
    'SHOPIFY_SHOP',
    'SHOPIFY_CLIENT_ID',
    'SHOPIFY_CLIENT_SECRET'
  ];

  for (const key of required) {
    if (
      !env[key] ||
      !String(env[key]).trim()
    ) {
      throw new Error(
        `Missing Cloudflare environment variable: ${key}`
      );
    }
  }
}


/* =========================================================
   SHOPIFY APP PROXY SIGNATURE
========================================================= */

async function verifyAppProxySignature(url, secret) {
  if (!secret) {
    throw new Error(
      'SHOPIFY_CLIENT_SECRET is missing.'
    );
  }

  const params =
    new URLSearchParams(url.search);

  const providedSignature =
    params.get('signature');

  if (!providedSignature) {
    return false;
  }

  params.delete('signature');

  /*
   * Shopify App Proxy signature:
   *
   * 1. Remove signature
   * 2. Group duplicate parameters
   * 3. Sort parameter names
   * 4. Join duplicate values with commas
   * 5. Concatenate without "&"
   */

  const grouped = {};

  for (const [key, value] of params.entries()) {
    if (!grouped[key]) {
      grouped[key] = [];
    }

    grouped[key].push(value);
  }

  const message =
    Object.keys(grouped)
      .sort()
      .map((key) => {
        return `${key}=${grouped[key].join(',')}`;
      })
      .join('');

  const encoder =
    new TextEncoder();

  const cryptoKey =
    await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      {
        name: 'HMAC',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    );

  const signatureBuffer =
    await crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      encoder.encode(message)
    );

  const calculatedSignature =
    Array
      .from(
        new Uint8Array(signatureBuffer)
      )
      .map((byte) =>
        byte
          .toString(16)
          .padStart(2, '0')
      )
      .join('');

  return timingSafeEqual(
    calculatedSignature,
    providedSignature
  );
}


function timingSafeEqual(a, b) {
  if (
    typeof a !== 'string' ||
    typeof b !== 'string' ||
    a.length !== b.length
  ) {
    return false;
  }

  let result = 0;

  for (
    let i = 0;
    i < a.length;
    i++
  ) {
    result |=
      a.charCodeAt(i) ^
      b.charCodeAt(i);
  }

  return result === 0;
}


/* =========================================================
   SHOPIFY ACCESS TOKEN
========================================================= */

async function getShopifyAccessToken(env) {
  const endpoint =
    `https://${env.SHOPIFY_SHOP}/admin/oauth/access_token`;

  const body =
    new URLSearchParams();

  body.set(
    'grant_type',
    'client_credentials'
  );

  body.set(
    'client_id',
    env.SHOPIFY_CLIENT_ID
  );

  body.set(
    'client_secret',
    env.SHOPIFY_CLIENT_SECRET
  );

  const response =
    await fetch(endpoint, {
      method: 'POST',

      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded'
      },

      body
    });

  let data;

  try {
    data = await response.json();
  } catch (error) {
    console.error(
      'Unable to parse Shopify token response:',
      error
    );

    throw new Error(
      'Invalid response from Shopify authentication.'
    );
  }

  if (
    !response.ok ||
    !data.access_token
  ) {
    console.error(
      'Shopify token error:',
      data
    );

    throw new Error(
      'Unable to authenticate with Shopify.'
    );
  }

  return data.access_token;
}


/* =========================================================
   SHOPIFY GRAPHQL
========================================================= */

async function shopifyGraphQL(
  env,
  accessToken,
  query,
  variables = {}
) {
  const endpoint =
    `https://${env.SHOPIFY_SHOP}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;

  const response =
    await fetch(endpoint, {
      method: 'POST',

      headers: {
        'Content-Type':
          'application/json',

        'X-Shopify-Access-Token':
          accessToken
      },

      body: JSON.stringify({
        query,
        variables
      })
    });

  let data;

  try {
    data = await response.json();
  } catch (error) {
    console.error(
      'Shopify response JSON error:',
      error
    );

    throw new Error(
      'Shopify returned an invalid response.'
    );
  }

  if (!response.ok) {
    console.error(
      'Shopify HTTP error:',
      response.status,
      data
    );

    throw new Error(
      `Shopify API request failed with HTTP ${response.status}.`
    );
  }

  if (
    data.errors &&
    data.errors.length
  ) {
    console.error(
      'Shopify GraphQL errors:',
      data.errors
    );

    throw new Error(
      data.errors
        .map((error) => error.message)
        .join(', ')
    );
  }

  return data.data;
}


/* =========================================================
   QUANTITY DISCOUNTS

   Must match Liquid:

   1 - 4   = 0%
   5 - 10  = 5%
   11 - 20 = 8%
   21+     = 10%
========================================================= */

function getDiscountPercentage(quantity) {
  const qty =
    Math.max(
      1,
      parseInt(quantity, 10) || 1
    );

  if (qty >= 21) {
    return 10;
  }

  if (qty >= 11) {
    return 8;
  }

  if (qty >= 5) {
    return 5;
  }

  return 0;
}


/* =========================================================
   CREATE ORDER
========================================================= */

async function createOrder(
  request,
  env
) {
  let payload;

  /* -------------------------
     Parse JSON
  ------------------------- */

  try {
    payload =
      await request.json();
  } catch (error) {
    return json(
      {
        success: false,
        message:
          'Invalid JSON request.'
      },
      400
    );
  }


  /* =====================================================
     CUSTOMER
  ===================================================== */

  const customer =
    payload.customer || {};

  const email =
    String(
      customer.email || ''
    )
      .trim()
      .toLowerCase();

  if (!email) {
    return json(
      {
        success: false,
        message:
          'Email address is required.'
      },
      400
    );
  }


  /* =====================================================
     ITEMS
  ===================================================== */

  if (
    !Array.isArray(payload.items) ||
    !payload.items.length
  ) {
    return json(
      {
        success: false,
        message:
          'Order contains no products.'
      },
      400
    );
  }


  let items;

  try {
    items =
      payload.items.map((item) => {

        const variantId =
          String(
            item.variant_id || ''
          )
            .replace(
              'gid://shopify/ProductVariant/',
              ''
            )
            .trim();

        const quantity =
          Math.max(
            1,
            parseInt(
              item.quantity,
              10
            ) || 1
          );

        if (
          !/^\d+$/.test(variantId)
        ) {
          throw new Error(
            'Invalid Shopify variant ID.'
          );
        }

        return {
          variantId:
            `gid://shopify/ProductVariant/${variantId}`,

          quantity
        };
      });

  } catch (error) {
    return json(
      {
        success: false,
        message:
          error.message ||
          'Invalid order item.'
      },
      400
    );
  }


  /* =====================================================
     AUTHENTICATE WITH SHOPIFY
  ===================================================== */

  const accessToken =
    await getShopifyAccessToken(env);


  /* =====================================================
     FETCH REAL VARIANT PRICES

     IMPORTANT:
     We never trust prices sent from storefront JavaScript.
  ===================================================== */

  const variantIds =
    items.map(
      (item) => item.variantId
    );


  const variantData =
    await shopifyGraphQL(
      env,
      accessToken,
      `
        query GetOrderVariants(
          $ids: [ID!]!
        ) {

          shop {
            currencyCode
          }

          nodes(ids: $ids) {

            ... on ProductVariant {

              id
              title
              price

              product {
                id
                title
              }

            }

          }

        }
      `,
      {
        ids: variantIds
      }
    );


  if (
    !variantData ||
    !variantData.shop
  ) {
    throw new Error(
      'Unable to load Shopify variant information.'
    );
  }


  const currency =
    variantData.shop.currencyCode;


  const variantMap =
    new Map();


  for (
    const variant
    of variantData.nodes || []
  ) {
    if (
      variant &&
      variant.id
    ) {
      variantMap.set(
        variant.id,
        variant
      );
    }
  }


  /* =====================================================
     BUILD ORDER LINE ITEMS
  ===================================================== */

  const lineItems =
    items.map((item) => {

      const variant =
        variantMap.get(
          item.variantId
        );

      if (!variant) {
        throw new Error(
          'One of the selected Shopify variants no longer exists.'
        );
      }


      const normalPrice =
        Number(
          variant.price
        );


      if (
        !Number.isFinite(normalPrice)
      ) {
        throw new Error(
          'Unable to determine Shopify variant price.'
        );
      }


      const discount =
        getDiscountPercentage(
          item.quantity
        );


      const discountedPrice =
        normalPrice *
        (100 - discount) /
        100;


      return {

        variantId:
          item.variantId,

        quantity:
          item.quantity,

        /*
         * Force the order line price to match
         * the wholesale quantity-discount price.
         */

        priceSet: {
          shopMoney: {
            amount:
              discountedPrice.toFixed(2),

            currencyCode:
              currency
          }
        },

        properties: [
          {
            name:
              'Quantity Discount',

            value:
              `${discount}%`
          }
        ]

      };
    });


  /* =====================================================
     ORDER NOTE
  ===================================================== */

  const noteParts = [];


  if (payload.note) {
    noteParts.push(
      String(
        payload.note
      ).trim()
    );
  }


  if (customer.company) {
    noteParts.push(
      `Company: ${String(customer.company).trim()}`
    );
  }


  if (customer.phone) {
    noteParts.push(
      `Phone: ${String(customer.phone).trim()}`
    );
  }


  noteParts.push(
    'Source: Custom Order Builder'
  );


  /* =====================================================
     SHOPIFY ORDERCREATE MUTATION
  ===================================================== */

  const mutation = `

    mutation CreateWholesaleOrder(
      $order: OrderCreateOrderInput!,
      $options: OrderCreateOptionsInput
    ) {

      orderCreate(
        order: $order,
        options: $options
      ) {

        order {

          id
          name
          email

          totalPriceSet {

            shopMoney {
              amount
              currencyCode
            }

          }

        }

        userErrors {
          field
          message
        }

      }

    }

  `;


  /* =====================================================
     ORDER VARIABLES
  ===================================================== */

  const variables = {

    order: {

      email,

      lineItems,

      customer: {

        toUpsert: {

          email,

          firstName:
            String(
              customer.first_name || ''
            ).trim(),

          lastName:
            String(
              customer.last_name || ''
            ).trim()

        }

      },

      note:
        noteParts
          .filter(Boolean)
          .join('\n'),

      tags: [
        'Custom Order Builder',
        'Wholesale'
      ]

    },


    options: {

      /*
       * Send normal Shopify order
       * confirmation email to customer.
       */

      sendReceipt:
        true,


      /*
       * No fulfillment confirmation
       * email yet.
       */

      sendFulfillmentReceipt:
        false,


      /*
       * IMPORTANT
       * =========
       *
       * Previously:
       *
       * DECREMENT_OBEYING_POLICY
       *
       * That caused:
       *
       * "Unable to reserve inventory"
       *
       * BYPASS allows the wholesale order
       * to be created without Shopify
       * attempting to reserve inventory.
       */

      inventoryBehaviour:
        'BYPASS'

    }

  };


  /* =====================================================
     CREATE ORDER
  ===================================================== */

  console.log(
    'Creating Shopify order:',
    {
      email,
      itemCount:
        lineItems.length,
      currency
    }
  );


  const result =
    await shopifyGraphQL(
      env,
      accessToken,
      mutation,
      variables
    );


  if (
    !result ||
    !result.orderCreate
  ) {
    console.error(
      'Invalid orderCreate response:',
      result
    );

    throw new Error(
      'Shopify returned an invalid order creation response.'
    );
  }


  const orderCreate =
    result.orderCreate;


  /* =====================================================
     SHOPIFY USER ERRORS
  ===================================================== */

  if (
    orderCreate.userErrors &&
    orderCreate.userErrors.length
  ) {

    console.error(
      'orderCreate userErrors:',
      orderCreate.userErrors
    );


    const errorMessage =
      orderCreate.userErrors
        .map((error) => {

          const field =
            Array.isArray(error.field)
              ? error.field.join('.')
              : error.field;

          if (field) {
            return `${field}: ${error.message}`;
          }

          return error.message;

        })
        .join(', ');


    return json(
      {
        success: false,
        message:
          errorMessage
      },
      400
    );
  }


  /* =====================================================
     CHECK ORDER EXISTS
  ===================================================== */

  if (!orderCreate.order) {
    return json(
      {
        success: false,
        message:
          'Shopify did not create the order.'
      },
      500
    );
  }


  /* =====================================================
     SUCCESS
  ===================================================== */

  console.log(
    'Shopify order created:',
    {
      id:
        orderCreate.order.id,

      name:
        orderCreate.order.name,

      email:
        orderCreate.order.email
    }
  );


  return json({

    success: true,

    orderId:
      orderCreate.order.id,

    orderName:
      orderCreate.order.name,

    total:
      orderCreate.order
        .totalPriceSet
        ?.shopMoney
        ?.amount,

    currency:
      orderCreate.order
        .totalPriceSet
        ?.shopMoney
        ?.currencyCode

  });
}


/* =========================================================
   CLOUDFLARE WORKER
========================================================= */

export default {

  async fetch(
    request,
    env
  ) {

    try {

      /* ===================================================
         VALIDATE ENVIRONMENT
      =================================================== */

      validateEnvironment(env);


      const url =
        new URL(
          request.url
        );


      console.log(
        `${request.method} ${url.pathname}`
      );


      /* ===================================================
         HEALTH CHECK
      =================================================== */

      if (
        url.pathname === '/' ||
        url.pathname === '/health' ||
        url.pathname === '/api/health'
      ) {

        return json({
          success: true,
          service:
            'Shopify Order Builder API'
        });

      }


      /* ===================================================
         CREATE ORDER ROUTE
      =================================================== */

      if (
        url.pathname ===
        '/api/create-order'
      ) {

        /* -----------------------------------------------
           POST ONLY
        ----------------------------------------------- */

        if (
          request.method !==
          'POST'
        ) {

          return json(
            {
              success: false,
              message:
                'Method not allowed.'
            },
            405
          );

        }


        /* -----------------------------------------------
           VERIFY SHOPIFY APP PROXY SIGNATURE
        ----------------------------------------------- */

        const validProxy =
          await verifyAppProxySignature(
            url,
            env.SHOPIFY_CLIENT_SECRET
          );


        if (!validProxy) {

          console.error(
            'Invalid Shopify App Proxy signature.'
          );

          return json(
            {
              success: false,
              message:
                'Invalid Shopify app proxy signature.'
            },
            401
          );

        }


        /* -----------------------------------------------
           VERIFY STORE
        ----------------------------------------------- */

        const proxyShop =
          url.searchParams.get(
            'shop'
          );


        if (
          proxyShop !==
          env.SHOPIFY_SHOP
        ) {

          console.error(
            'Invalid Shopify shop:',
            proxyShop
          );

          return json(
            {
              success: false,
              message:
                'Invalid Shopify shop.'
            },
            403
          );

        }


        /* -----------------------------------------------
           CREATE ORDER
        ----------------------------------------------- */

        return await createOrder(
          request,
          env
        );

      }


      /* ===================================================
         NOT FOUND
      =================================================== */

      return json(
        {
          success: false,
          message:
            'Not found.'
        },
        404
      );


    } catch (error) {

      console.error(
        'Worker error:',
        error
      );

      console.error(
        'Worker error message:',
        error?.message
      );

      console.error(
        'Worker error stack:',
        error?.stack
      );


      return json(
        {
          success: false,

          message:
            error?.message ||
            'Internal server error.'
        },
        500
      );

    }

  }

};
