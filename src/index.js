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
   SHOPIFY APP PROXY SIGNATURE
========================================================= */

async function verifyAppProxySignature(url, secret) {
  const params = new URLSearchParams(url.search);

  const providedSignature = params.get('signature');

  if (!providedSignature) {
    return false;
  }

  params.delete('signature');

  /*
   * Shopify app proxy signing requires:
   * key=value pairs sorted alphabetically,
   * duplicate values joined with commas,
   * then concatenated without "&".
   */

  const grouped = {};

  for (const [key, value] of params.entries()) {
    if (!grouped[key]) {
      grouped[key] = [];
    }

    grouped[key].push(value);
  }

  const message = Object.keys(grouped)
    .sort()
    .map((key) => {
      return `${key}=${grouped[key].join(',')}`;
    })
    .join('');

  const encoder = new TextEncoder();

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    {
      name: 'HMAC',
      hash: 'SHA-256'
    },
    false,
    ['sign']
  );

  const signatureBuffer = await crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    encoder.encode(message)
  );

  const calculatedSignature = Array
    .from(new Uint8Array(signatureBuffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
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

  for (let i = 0; i < a.length; i++) {
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

  const body = new URLSearchParams();

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

  const response = await fetch(endpoint, {
    method: 'POST',

    headers: {
      'Content-Type':
        'application/x-www-form-urlencoded'
    },

    body
  });

  const data = await response.json();

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

  const response = await fetch(endpoint, {
    method: 'POST',

    headers: {
      'Content-Type': 'application/json',

      'X-Shopify-Access-Token':
        accessToken
    },

    body: JSON.stringify({
      query,
      variables
    })
  });

  const data = await response.json();

  if (!response.ok) {
    console.error(
      'Shopify HTTP error:',
      response.status,
      data
    );

    throw new Error(
      'Shopify API request failed.'
    );
  }

  if (data.errors?.length) {
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
   DISCOUNT
   Same rules as your Liquid:
   1-4   = 0%
   5-10  = 5%
   11-20 = 8%
   21+   = 10%
========================================================= */

function getDiscountPercentage(quantity) {
  if (quantity >= 21) {
    return 10;
  }

  if (quantity >= 11) {
    return 8;
  }

  if (quantity >= 5) {
    return 5;
  }

  return 0;
}


/* =========================================================
   CREATE ORDER
========================================================= */

async function createOrder(request, env, proxyUrl) {
  let payload;

  try {
    payload = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: 'Invalid JSON request.'
      },
      400
    );
  }


  /* -------------------------
     Validate customer
  ------------------------- */

  const customer =
    payload.customer || {};

  const email =
    String(customer.email || '')
      .trim()
      .toLowerCase();

  if (!email) {
    return json(
      {
        success: false,
        message: 'Email address is required.'
      },
      400
    );
  }


  /* -------------------------
     Validate items
  ------------------------- */

  if (
    !Array.isArray(payload.items) ||
    !payload.items.length
  ) {
    return json(
      {
        success: false,
        message: 'Order contains no products.'
      },
      400
    );
  }

  const items =
    payload.items.map((item) => {
      const variantId =
        String(item.variant_id || '')
          .replace(
            'gid://shopify/ProductVariant/',
            ''
          )
          .trim();

      const quantity =
        Math.max(
          1,
          parseInt(item.quantity, 10) || 1
        );

      if (!/^\d+$/.test(variantId)) {
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


  /* -------------------------
     Authenticate
  ------------------------- */

  const accessToken =
    await getShopifyAccessToken(env);


  /* -------------------------
     Load REAL Shopify prices

     Never trust frontend prices.
  ------------------------- */

  const variantIds =
    items.map((item) => item.variantId);

  const variantData =
    await shopifyGraphQL(
      env,
      accessToken,
      `
        query GetOrderVariants($ids: [ID!]!) {
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

  const currency =
    variantData.shop.currencyCode;

  const variantMap =
    new Map();

  for (const variant of variantData.nodes) {
    if (variant?.id) {
      variantMap.set(
        variant.id,
        variant
      );
    }
  }


  /* -------------------------
     Build secure line items
  ------------------------- */

  const lineItems =
    items.map((item) => {
      const variant =
        variantMap.get(item.variantId);

      if (!variant) {
        throw new Error(
          'One of the selected Shopify variants no longer exists.'
        );
      }

      const normalPrice =
        Number(variant.price);

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
         * This makes the Shopify order total
         * match the quantity-discount pricing
         * displayed by your builder.
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
            name: 'Quantity Discount',
            value: `${discount}%`
          }
        ]
      };
    });


  /* -------------------------
     Order notes
  ------------------------- */

  const noteParts = [];

  if (payload.note) {
    noteParts.push(
      String(payload.note)
    );
  }

  if (customer.company) {
    noteParts.push(
      `Company: ${customer.company}`
    );
  }

  noteParts.push(
    'Source: Custom Order Builder'
  );


  /* -------------------------
     Shopify OrderCreate
  ------------------------- */

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
        noteParts.join('\n'),

      tags: [
        'Custom Order Builder',
        'Wholesale'
      ]
    },

    options: {
      /*
       * Customer gets Shopify's
       * order confirmation email.
       */
      sendReceipt: true,

      sendFulfillmentReceipt: false,

      /*
       * Claim inventory.
       */
      inventoryBehaviour:
        'DECREMENT_OBEYING_POLICY'
    }
  };

  const result =
    await shopifyGraphQL(
      env,
      accessToken,
      mutation,
      variables
    );

  const orderCreate =
    result.orderCreate;

  if (
    orderCreate.userErrors?.length
  ) {
    console.error(
      'orderCreate userErrors:',
      orderCreate.userErrors
    );

    return json(
      {
        success: false,

        message:
          orderCreate.userErrors
            .map(
              (error) =>
                error.message
            )
            .join(', ')
      },
      400
    );
  }

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
   WORKER
========================================================= */

export default {
  async fetch(request, env) {
    try {
      const url =
        new URL(request.url);

      /*
       * Shopify app proxy sends:
       * /api/create-order
       */
      if (
        url.pathname ===
        '/api/create-order'
      ) {
        if (request.method !== 'POST') {
          return json(
            {
              success: false,
              message: 'Method not allowed.'
            },
            405
          );
        }


        /* -------------------------
           Verify Shopify App Proxy
        ------------------------- */

        const validProxy =
          await verifyAppProxySignature(
            url,
            env.SHOPIFY_CLIENT_SECRET
          );

        if (!validProxy) {
          return json(
            {
              success: false,
              message:
                'Invalid Shopify app proxy signature.'
            },
            401
          );
        }


        /* -------------------------
           Only accept our shop
        ------------------------- */

        const proxyShop =
          url.searchParams.get('shop');

        if (
          proxyShop !==
          env.SHOPIFY_SHOP
        ) {
          return json(
            {
              success: false,
              message: 'Invalid Shopify shop.'
            },
            403
          );
        }


        return await createOrder(
          request,
          env,
          url
        );
      }


      if (
        url.pathname === '/' ||
        url.pathname === '/health'
      ) {
        return json({
          success: true,
          service:
            'Shopify Order Builder API'
        });
      }


      return json(
        {
          success: false,
          message: 'Not found.'
        },
        404
      );

    } catch (error) {
      console.error(
        'Worker error:',
        error
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
