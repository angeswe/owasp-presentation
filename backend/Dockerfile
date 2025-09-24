# Use an official Node.js runtime as a parent image
FROM node:20-alpine

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to leverage Docker cache
COPY package*.json ./

# Install app dependencies
RUN npm install --only=production

# Bundle app source
COPY . .

# Build TypeScript source
RUN npm run build

# The backend needs the database file
# The database is located at the root of the backend directory
COPY database ./database

# The backend runs on port 3001
EXPOSE 3001

# Command to run the application
CMD [ "npm", "start" ]
