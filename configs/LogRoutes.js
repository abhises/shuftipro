// logRoutes.mjs or logRoutes.js (if "type": "module" in package.json)
const logRoutes = {
  system: {
    retention: "180d",
    category: "system",
    description: "System-level events",
    logs: [
      {
        flag: "startup",
        path: "system/startup/{time:DD-MM-YYYY}.log",
        PCI_compliance: false,
        critical: false,
        description: "Application startup event",
      },
      {
        flag: "shutdown",
        path: "system/shutdown/{time:DD-MM-YYYY}.log",
        PCI_compliance: false,
        critical: true,
        description: "Application shutdown event",
      },
    ],
  },

  auth: {
    retention: "30d",
    category: "authentication",
    description: "Authentication events",
    logs: [
      {
        flag: "login",
        path: "auth/login/{userId:UID}/{time:DD-MM-YYYY}.log",
        PCI_compliance: true,
        critical: false,
        description: "User login event",
      },
      {
        flag: "logout",
        path: "auth/logout/{userId:UID}/{time:DD-MM-YYYY}.log",
        PCI_compliance: false,
        critical: false,
        description: "User logout event",
      },
    ],
  },

  payments: {
    retention: "90d",
    category: "payments",
    description: "Payment processing events",
    logs: [
      {
        flag: "transaction",
        path: "payments/transaction/{transactionId}/{time:DD-MM-YYYY}.log",
        PCI_compliance: true,
        critical: true,
        description: "Payment transaction event",
      },
      {
        flag: "refund",
        path: "payments/refund/{transactionId}/{time:DD-MM-YYYY}.log",
        PCI_compliance: true,
        critical: false,
        description: "Refund processed event",
      },
    ],
  },

  orders: {
    retention: "60d",
    category: "orders",
    description: "Order events",
    logs: [
      {
        flag: "order_placed",
        path: "orders/place/{orderId}/{time:DD-MM-YYYY}.log",
        PCI_compliance: true,
        critical: true,
        description: "Order placed event",
      },
    ],
  },

  products: {
    retention: "90d",
    category: "products",
    description: "Product-related logs",
    logs: [
      {
        flag: "product_viewed",
        path: "products/view/{productId}/{time:DD-MM-YYYY}.log",
        PCI_compliance: false,
        critical: false,
        description: "Product viewed event",
      },
    ],
  },

  subscriptions: {
    retention: "120d",
    category: "subscriptions",
    description: "Subscription-related logs",
    logs: [
      {
        flag: "subscription_created",
        path: "subscriptions/create/{SubscriptionId}/{time:DD-MM-YYYY}.log",
        PCI_compliance: true,
        critical: true,
        description: "Subscription created",
      },
    ],
  },
  chime: {
    category: "chime",
    description: "AWS Chime attendee logs",
    retention: "30d",
    logs: [
      {
        flag: "CHIME_ADD_ATTENDEE",
        path: "chime/attendees/{meetingId:UID}/{timestamp:DD-MM-YYYY}.log",
        PCI_compliance: false,
        critical: false,
      },
      {
        flag: "CHIME_ADD_ATTENDEE_ERROR",
        path: "chime/errors/addAttendee/{meetingId:UID}/{timestamp:DD-MM-YYYY}.log",
        PCI_compliance: false,
        critical: true,
      },
    ],
  },
};

export default logRoutes;
