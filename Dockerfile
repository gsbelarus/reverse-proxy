# Use an official Node.js runtime as the base image
FROM node:25-alpine 

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install production dependencies
RUN npm ci --omit=dev

# Copy only the runtime application code; certificates are mounted at runtime
COPY src ./src

# Expose the port on which the server will listen
EXPOSE 80 443

# Start the server
CMD [ "node", "src/index.js" ]
