# Shufti Project

## Project Overview

This project implements the ShuftiPro KYC service using **Node.js** and **Express.js**.  
It provides APIs to create verification sessions, handle webhook events, and manage verification records. The project uses a **modular folder structure** for easy maintainability.

---

## Folder Structure

shufti/
│
├── app.js # Main application entry point
├── index.js # Server start file
├── createTables.js # Script to create database tables
├── package.json # Project dependencies and scripts
│
├── configs/ # Configuration files
│ └── Logroutes.js # Logger and routing configuration
│
├── constants/ # Export project constants
│ └── constants.js
│
├── helper/ # Helper functions
│ └── index.js
│
├── routes/ # Express routes
│ └── index.js
│
├── utils/ # Utilities (SafeUtils, Logger, ErrorHandler, etc.)
│ └── index.js
│
├── service/ # Main business logic
│ └── ShuftiProKyc.js
│
└── test/ # Test files
└── test.js

## 1nstall dependencies:

1. npm install

## Running server

2. npm run dev

## Dependencies

    express – Web framework

    body-parser – Parse incoming request bodies

    dotenv – Load environment variables

    luxon / moment – Date and time handling

    @aws-sdk/client-s3 – AWS S3 SDK

    nodemon – Development server auto-reload
