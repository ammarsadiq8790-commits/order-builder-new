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
   HTML ESCAPE
========================================================= */

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}


/* =========================================================
   ENVIRONMENT VALIDATION
========================================================= */

function validateEnvironment(env) {
  const required = [
    'SHOPIFY_SHOP',
    'SHOPIFY_CLIENT_ID',
    'SHOPIFY_CLIENT_SECRET',
    'RESEND_API_KEY',
    'EMAIL_FROM'
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
    data =
      await response.json();
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
    data =
      await response.json();
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
   FORMAT MONEY
========================================================= */

function formatMoney(amount, currency) {
  const number =
    Number(amount || 0);

  try {
    return new Intl.NumberFormat(
      'en-US',
      {
        style: 'currency',
        currency: currency || 'USD'
      }
    ).format(number);
  } catch (error) {
    return `${currency || 'USD'} ${number.toFixed(2)}`;
  }
}


/* =========================================================
   BUILD EMAIL PRODUCT ROWS
========================================================= */

function buildEmailProductRows(
  emailItems,
  currency
) {
  return emailItems
    .map((item) => {
      const productTitle =
        escapeHtml(
          item.productTitle
        );

      const variantTitle =
        escapeHtml(
          item.variantTitle
        );

      const quantity =
        Number(
          item.quantity
        );

      const unitPrice =
        Number(
          item.price
        );

      const lineTotal =
        unitPrice * quantity;

      return `
        <tr>
          <td
            style="
              padding:15px 8px;
              border-bottom:1px solid #eeeeee;
              font-size:14px;
              line-height:1.5;
            "
          >
            <strong>
              ${productTitle}
            </strong>

            ${
              variantTitle &&
              variantTitle !== 'Default Title'
                ? `
                  <div
                    style="
                      margin-top:3px;
                      color:#777777;
                      font-size:12px;
                    "
                  >
                    ${variantTitle}
                  </div>
                `
                : ''
            }
          </td>

          <td
            align="center"
            style="
              padding:15px 8px;
              border-bottom:1px solid #eeeeee;
              font-size:14px;
            "
          >
            ${quantity}
          </td>

          <td
            align="right"
            style="
              padding:15px 8px;
              border-bottom:1px solid #eeeeee;
              font-size:14px;
            "
          >
            ${formatMoney(lineTotal, currency)}
          </td>
        </tr>
      `;
    })
    .join('');
}


/* =========================================================
   BUILD PLAIN TEXT EMAIL
========================================================= */

function buildPlainTextEmail(
  customer,
  order,
  emailItems
) {
  const firstName =
    String(
      customer.first_name || ''
    ).trim();

  const orderName =
    String(
      order.name || 'Order'
    );

  const total =
    order
      .totalPriceSet
      ?.shopMoney
      ?.amount || '0.00';

  const currency =
    order
      .totalPriceSet
      ?.shopMoney
      ?.currencyCode || 'USD';

  const itemLines =
    emailItems
      .map((item) => {
        const quantity =
          Number(item.quantity);

        const price =
          Number(item.price);

        const lineTotal =
          quantity * price;

        const variant =
          item.variantTitle &&
          item.variantTitle !== 'Default Title'
            ? ` - ${item.variantTitle}`
            : '';

        return (
          `${item.productTitle}${variant}` +
          ` | Qty: ${quantity}` +
          ` | ${formatMoney(lineTotal, currency)}`
        );
      })
      .join('\n');

  return [
    firstName
      ? `Hi ${firstName},`
      : 'Hi,',

    '',

    'Thank you for your order.',

    `Your order number is ${orderName}.`,

    '',

    'Order details:',

    itemLines,

    '',

    `Order Total: ${formatMoney(total, currency)}`,

    '',

    'We have received your order successfully.',

    'We will contact you if we need any additional information regarding your order.'
  ].join('\n');
}


/* =========================================================
   SEND CUSTOMER EMAIL THROUGH RESEND
========================================================= */

async function sendOrderConfirmationEmail(
  env,
  {
    email,
    customer,
    order,
    emailItems
  }
) {
  const firstName =
    String(
      customer.first_name || ''
    ).trim();

  const orderName =
    String(
      order.name || 'Order'
    );

  const total =
    order
      .totalPriceSet
      ?.shopMoney
      ?.amount || '0.00';

  const currency =
    order
      .totalPriceSet
      ?.shopMoney
      ?.currencyCode || 'USD';

  const productRows =
    buildEmailProductRows(
      emailItems,
      currency
    );

  const safeFirstName =
    escapeHtml(firstName);

  const safeOrderName =
    escapeHtml(orderName);

  const html = `
    <!doctype html>

    <html>
      <head>
        <meta charset="utf-8">

        <meta
          name="viewport"
          content="width=device-width, initial-scale=1"
        >

        <title>
          Order Confirmation
        </title>
      </head>

      <body
        style="
          margin:0;
          padding:0;
          background:#f5f5f5;
          font-family:Arial, Helvetica, sans-serif;
          color:#222222;
        "
      >

        <table
          role="presentation"
          width="100%"
          cellspacing="0"
          cellpadding="0"
          border="0"
          style="
            background:#f5f5f5;
            padding:30px 15px;
          "
        >

          <tr>
            <td align="center">

              <table
                role="presentation"
                width="100%"
                cellspacing="0"
                cellpadding="0"
                border="0"
                style="
                  max-width:650px;
                  background:#ffffff;
                  border-radius:8px;
                "
              >

                <tr>
                  <td
                    style="
                      padding:35px 30px;
                      text-align:center;
                      border-bottom:1px solid #eeeeee;
                    "
                  >

                    <h1
                      style="
                        margin:0;
                        font-size:26px;
                        line-height:1.3;
                      "
                    >
                      Thank you for your order!
                    </h1>

                  </td>
                </tr>


                <tr>
                  <td
                    style="
                      padding:35px 30px;
                    "
                  >

                    <p
                      style="
                        margin:0 0 15px;
                        font-size:16px;
                        line-height:1.6;
                      "
                    >
                      ${
                        safeFirstName
                          ? `Hi ${safeFirstName},`
                          : 'Hi,'
                      }
                    </p>


                    <p
                      style="
                        margin:0 0 25px;
                        font-size:16px;
                        line-height:1.6;
                      "
                    >
                      We have received your order successfully.

                      Your order number is
                      <strong>
                        ${safeOrderName}
                      </strong>.
                    </p>


                    <table
                      role="presentation"
                      width="100%"
                      cellspacing="0"
                      cellpadding="0"
                      border="0"
                      style="
                        border-collapse:collapse;
                      "
                    >

                      <thead>
                        <tr>

                          <th
                            align="left"
                            style="
                              padding:12px 8px;
                              border-bottom:2px solid #222222;
                              font-size:13px;
                            "
                          >
                            Product
                          </th>

                          <th
                            align="center"
                            style="
                              padding:12px 8px;
                              border-bottom:2px solid #222222;
                              font-size:13px;
                            "
                          >
                            Qty
                          </th>

                          <th
                            align="right"
                            style="
                              padding:12px 8px;
                              border-bottom:2px solid #222222;
                              font-size:13px;
                            "
                          >
                            Total
                          </th>

                        </tr>
                      </thead>

                      <tbody>
                        ${productRows}
                      </tbody>

                    </table>


                    <table
                      role="presentation"
                      width="100%"
                      cellspacing="0"
                      cellpadding="0"
                      border="0"
                      style="
                        margin-top:25px;
                      "
                    >

                      <tr>
                        <td
                          align="right"
                          style="
                            font-size:18px;
                            line-height:1.5;
                          "
                        >

                          <strong>
                            Order Total:
                            ${formatMoney(total, currency)}
                          </strong>

                        </td>
                      </tr>

                    </table>


                    <p
                      style="
                        margin:30px 0 0;
                        font-size:14px;
                        line-height:1.6;
                        color:#666666;
                      "
                    >
                      We will contact you if we need any
                      additional information regarding your order.
                    </p>

                  </td>
                </tr>

              </table>

            </td>
          </tr>

        </table>

      </body>
    </html>
  `;

  const text =
    buildPlainTextEmail(
      customer,
      order,
      emailItems
    );


  console.log(
    'Sending customer confirmation email:',
    {
      email,
      orderName
    }
  );


  const emailPayload = {
    from:
      env.EMAIL_FROM,

    to: [
      email
    ],

    subject:
      `Order Confirmation ${orderName}`,

    html,

    text
  };


  /*
   * Optional.
   *
   * If EMAIL_REPLY_TO is configured in Cloudflare,
   * customer replies will go there.
   */

  if (
    env.EMAIL_REPLY_TO &&
    String(env.EMAIL_REPLY_TO).trim()
  ) {
    emailPayload.reply_to =
      String(
        env.EMAIL_REPLY_TO
      ).trim();
  }


  const response =
    await fetch(
      'https://api.resend.com/emails',
      {
        method: 'POST',

        headers: {
          'Authorization':
            `Bearer ${env.RESEND_API_KEY}`,

          'Content-Type':
            'application/json'
        },

        body:
          JSON.stringify(
            emailPayload
          )
      }
    );


  let data;

  try {
    data =
      await response.json();
  } catch (error) {
    console.error(
      'Unable to parse Resend response:',
      error
    );

    throw new Error(
      'Email service returned an invalid response.'
    );
  }


  if (!response.ok) {
    console.error(
      'Resend API error:',
      response.status,
      data
    );

    throw new Error(
      data?.message ||
      `Unable to send confirmation email. HTTP ${response.status}.`
    );
  }


  console.log(
    'Customer confirmation email accepted:',
    {
      email,
      orderName,

      emailId:
        data?.id || null
    }
  );


  return data;
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


  /*
   * Basic email validation
   */

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return json(
      {
        success: false,
        message:
          'Please enter a valid email address.'
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
      payload.items.map(
        (item) => {

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
            !/^\d+$/.test(
              variantId
            )
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
        }
      );

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
    await getShopifyAccessToken(
      env
    );


  /* =====================================================
     FETCH REAL VARIANT PRICES

     Do not trust prices from storefront JavaScript.
  ===================================================== */

  const variantIds =
    items.map(
      (item) =>
        item.variantId
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
        ids:
          variantIds
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

  const lineItems = [];

  const emailItems = [];


  for (const item of items) {

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
      !Number.isFinite(
        normalPrice
      )
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


    /*
     * Shopify order line item
     */

    lineItems.push({

      variantId:
        item.variantId,

      quantity:
        item.quantity,

      /*
       * Force order line price to match
       * wholesale quantity discount.
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

    });


    /*
     * Separate data used only for
     * confirmation email.
     */

    emailItems.push({

      productTitle:
        variant.product?.title ||
        'Product',

      variantTitle:
        variant.title ||
        '',

      quantity:
        item.quantity,

      price:
        discountedPrice.toFixed(2),

      discount

    });

  }


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
       * IMPORTANT:
       *
       * Customer order confirmation is
       * handled by Resend.
       *
       * Keep this false to prevent
       * duplicate customer emails.
       */

      sendReceipt:
        false,


      /*
       * No fulfillment confirmation
       * at order creation.
       */

      sendFulfillmentReceipt:
        false,


      /*
       * Preserve your existing wholesale
       * inventory behavior.
       */

      inventoryBehaviour:
        'BYPASS'

    }

  };


  /* =====================================================
     CREATE SHOPIFY ORDER
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
            Array.isArray(
              error.field
            )
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


  const createdOrder =
    orderCreate.order;


  /* =====================================================
     SHOPIFY ORDER SUCCESS
  ===================================================== */

  console.log(
    'Shopify order created:',
    {
      id:
        createdOrder.id,

      name:
        createdOrder.name,

      email:
        createdOrder.email
    }
  );


  /* =====================================================
     SEND CUSTOMER EMAIL
  ===================================================== */

  let emailSent =
    false;

  let emailId =
    null;

  let emailError =
    null;


  try {

    const emailResult =
      await sendOrderConfirmationEmail(
        env,
        {
          email,

          customer,

          order:
            createdOrder,

          emailItems
        }
      );


    emailSent =
      true;


    emailId =
      emailResult?.id ||
      null;


  } catch (error) {

    /*
     * IMPORTANT:
     *
     * The Shopify order already exists.
     *
     * Do not return success:false here.
     *
     * Otherwise frontend retry logic could
     * create a duplicate Shopify order.
     */

    emailError =
      error?.message ||
      'Unable to send confirmation email.';


    console.error(
      'ORDER CREATED BUT CUSTOMER EMAIL FAILED:',
      {
        orderId:
          createdOrder.id,

        orderName:
          createdOrder.name,

        customerEmail:
          email,

        error:
          emailError
      }
    );

  }


  /* =====================================================
     SUCCESS RESPONSE
  ===================================================== */

  return json({

    success:
      true,

    orderId:
      createdOrder.id,

    orderName:
      createdOrder.name,

    total:
      createdOrder
        .totalPriceSet
        ?.shopMoney
        ?.amount,

    currency:
      createdOrder
        .totalPriceSet
        ?.shopMoney
        ?.currencyCode,

    emailSent,

    emailId,

    /*
     * Keep this while testing.
     *
     * It lets us see the Resend error
     * without treating the Shopify order
     * as failed.
     */

    emailError

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

      validateEnvironment(
        env
      );


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
          success:
            true,

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
              success:
                false,

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
              success:
                false,

              message:
                'Invalid Shopify app proxy signature.'
            },
            401
          );

        }


        /* -----------------------------------------------
           VERIFY SHOP
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
              success:
                false,

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
          success:
            false,

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
          success:
            false,

          message:
            error?.message ||
            'Internal server error.'
        },
        500
      );

    }

  }

};
