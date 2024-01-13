/**
 * @swagger
 * /:
 *  get:
 *      summary: This api is for testing
 *      tags:
 *        - test
 *      description: This api is used for testing
 *      responses:
 *          200:
 *              description: to test get api
 */

/**
 * @swagger
 * /test/register:
 *  post:
 *      summary: admin registration for penetration testing
 *      tags:
 *        - test
 *      description: Password must have minimum 8 characters.
 *      requestBody:
 *          required: true
 *          description: Password must have minimum 8 characters.
 *          content:
 *              application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          username:
 *                              type: string
 *                          password:
 *                              type: string
 *                              
 *                          name:
 *                              type: string
 *                          role:
 *                              type: string
 *                              
 *      responses:
 *          200:
 *              description: added successfully
 *              content:
 *                 application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          user:
 *                              $ref: '#components/schemas/registersuccessful'
 *          400:
 *              description: Invalid password. Please follow the password policy. Password must have minimum 8 characters.
 *          409:
 *              description: Username has been taken
 *          500:
 *              description: Internal server error
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  $ref: '#components/schemas/errormessage'
 */




/**
 * @swagger
 * /register:
 *  post:
 *      summary: registration for new users requiring security approval
 *      tags:
 *        - User
 *      description: this api fetch data from mongodb. Password must have minimum 8 characters.
 *      requestBody:
 *          required: true
 *          description: Password must have minimum 8 characters.
 *          content:
 *              application/json:
 *                  schema:
 *                      $ref: '#components/schemas/registerinfo'
 *      responses:
 *          200:
 *              description: added successfully
 *              content:
 *                 application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          user:
 *                              $ref: '#components/schemas/registersuccessful'
 *          400:
 *              description: Invalid password. Please follow the password policy.
 *          409:
 *              description: Username has been taken
 *          500:
 *              description: Internal server error
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  $ref: '#components/schemas/errormessage'
 */

/**
 * @swagger
 * /resident/register:
 *  post:
 *      summary: Register a new resident (admin access only)
 *      tags:
 *        - Resident
 *      security:
 *          - Authorization: []
 *      requestBody:
 *          required: true
 *          content:
 *              application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          resident_name:
 *                              type: string
 *                          resident_phone_number:
 *                              type: string
 *                          resident_address:
 *                              type: string
 *      responses:
 *          200:
 *              description: resident added successfully
 *              content:
 *                 application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          user:
 *                              $ref: '#components/schemas/Resident'
 *          403:
 *              description: Unauthorized,admin access only
 *          500:
 *              description: Internal server error
 *              content:
 *                  application/json:
 *                      schema:
 *                          type: object
 *                          properties:
 *                              message:
 *                                  $ref: '#components/schemas/errormessage'
 */




/**
 * @swagger
 *  /login:
 *    post:
 *      summary: Login for users
 *      tags:
 *        - User
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *               type: object
 *               properties:
 *                 username:
 *                  type: string
 *                 password:
 *                  type: string
 *      responses:
 *        200:
 *          description: Successful login
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                  username:
 *                    type: string
 *                    description: Username of the logged-in user
 *                  message:
 *                    type: string
 *                    description: Login successful message
 *                  accesstoken:
 *                    type: string
 *                    description: Generated access token for the logged-in user
 *        401:
 *          description: Unauthorized - Wrong password
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized Wrong password
 *        404:
 *          description: Username not found
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Username not found
 *        409:
 *          description: User is already logged in
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: User is already logged in
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                 $ref: '#components/schemas/errormessage'
 *                
 */


/**
 * @swagger
 *  /showjwt:
 *    get:
 *      summary: Display user information from JWT token
 *      tags:
 *        - test
 *      security:
 *        - Authorization: []
 *      responses:
 *        200:
 *          description: Successful retrieval of user information
 *          content:
 *            application/json:
 *              schema:
 *                $ref: '#components/schemas/jwtinfo'
 *                description: User information retrieved from JWT token
 *        401:
 *          description: Unauthorized - Invalid or missing token
 *          
 */



/**
 * @swagger
 *  /logout:
 *    patch:
 *      summary: Logout user
 *      tags:
 *        - User
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                username:
 *                  type: string
 *      responses:
 *        200:
 *          description: Successfully logged out
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Successfully logged out
 * 
 *        400:
 *          description: User has already logged out or invalid request
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: User has already logged out or invalid request
 * 
 *        404:
 *          description: Username not found
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Username not found
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                 $ref: '#components/schemas/errormessage'
 */


/**
 * @swagger
 *  /visitor/register:
 *    post:
 *      summary: Register a visitor for a user
 *      tags:
 *        - Visitor
 *      security:
 *        - Authorization: []
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *               type: object
 *               properties:
 *                  full_name:
 *                    type: string
 *                  phone_number:
 *                    type: string
 *                  email:
 *                    type: string
 *                    format: email
 *                  license_number:
 *                    type: string
 *               required:
 *                  - full_name
 *                  - phone_number
 *                  - email
 *                  - license_number
 *      responses:
 *        200:
 *          description: Visitor registered successfully
 *          content:
 *            application/json:
 *              schema:
 *                $ref: '#components/schemas/Visitor'
 * 
 *        401:
 *          description: Unauthorized - User not logged in
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Please login
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'
 */


/**
 * @swagger
 *  /visitor/visitor_pass/{id}:
 *    post:
 *      summary:  Create a new visitor pass for the specified visitor.
 *      tags:
 *        - Visitor
 *      security:
 *        - Authorization: []
 *      parameters:
 *          - in: path
 *            name: id
 *            required: true
 *            description: ID of the visitor to create visitor pass
 *            schema:
 *              type: string
 *      requestBody:
 *        required: true
 *        description: The visitor pass details
 *        content:
 *          application/json:
 *            schema:
 *               type: object
 *               properties:
 *                resident_number:
 *                  type: number
 *                purpose_of_visit:
 *                  type: string
 *                remarks:
 *                  type: string
 *               required:
 *                  - purpose_of_visit
 *                  - resident_number
 *      responses:
 *        201:
 *          description: Successfully created a new visitor pass
 *          content:
 *            application/json:
 *              example:
 *                  visitor_id: 123
 *                  resident_number: 1
 *                  purpose_of_visit: "meeting"
 *                  approval: false
 *                  remarks: "No special remarks"
 * 
 *        401:
 *          description: Unauthorized - User not logged in
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Please login
 *        403:
 *          description: The visitor does not belong to this user or insufficient permissions
 * 
 *        404:
 *          description: Visitor not found for this user
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Visitor not found for this user
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'
 */


/**
 * @swagger
 *  /read/user:
 *    get:
 *      summary: Retrieve own user information
 *      security:
 *        - Authorization: []
 *      tags:
 *        - Read
 *      description: Retrieves the user document if the user is logged in
 *      responses:
 *        200:
 *          description: Successful operation
 *          content:
 *            application/json:
 *              schema:
 *                $ref: '#/components/schemas/User'
 *        401:
 *          description: Unauthorized, please login
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized, please login
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                 $ref: '#components/schemas/errormessage'
 *                
 */


/**
 * @swagger
 *  /read/visitor:
 *    get:
 *      summary: Retrieve own visitor information
 *      security:
 *        - Authorization: []
 *      tags:
 *        - Read
 *      description: Retrieves the visitor document if the user is logged in
 *      responses:
 *        200:
 *          description: Successful operation
 *          content:
 *            application/json:
 *              schema:
 *                type: array
 *                items:
 *                  $ref: '#/components/schemas/Visitor'
 *        401:
 *          description: Unauthorized, please login
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized, please login
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                 $ref: '#components/schemas/errormessage'
 *                
 */


/**
 * @swagger
 *  /read/visitor_pass:
 *    get:
 *      summary: Read all visitor passes for all visitors (Logged-in User)
 *      description: Retrieves all visitor passes for all visitors associated with the logged-in user.
 *      security:
 *        - Authorization: []
 *      tags:
 *        - Read
 *      responses:
 *        200:
 *          description: Successful response with a JSON object representing passes for each visitor
 *        401:
 *          description: Unauthorized, please login
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized, please login
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                 $ref: '#components/schemas/errormessage'
 *                
 */


/**
 * @swagger
 *  /read/visitor_pass/{id}:
 *    get:
 *      summary: Read one visitor pass by ID
 *      description: Retrieves details of a visitor pass based on its ID.
 *      tags:
 *        - Read
 *      security:
 *        - Authorization: []
 *      parameters:
 *        - in: path
 *          name: id
 *          required: true
 *          description: The ID of the visitor pass to retrieve
 *          schema:
 *            type: string
 *      responses:
 *        200:
 *          description: OK. Visitor pass details retrieved successfully.
 *          content:
 *            application/json:
 *              schema:
 *                $ref: '#components/schemas/Pass'
 * 
 *        401:
 *          description: Unauthorized. Please login.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized. Please login.
 * 
 *        403:
 *          description: Forbidden, visitor pass does not belong to the logged-in user's visitor
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Forbidden, visitor pass does not belong to the logged-in user's visitor
 * 
 *        404:
 *          description: Visitor pass not found.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Visitor pass not found.
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'          
 */

/**
 * @swagger
 *  /security/pass/hp/{id}:
 *    get:
 *      summary: Get visitor pass details by ID
 *      description: Retrieves the phone number of the visitor associated with the specified pass ID.
 *      tags:
 *        - Security
 *      security:
 *        - Authorization: []
 *      parameters:
 *        - in: path
 *          name: id
 *          required: true
 *          description: ID of the visitor pass to retrieve its visitor phone number
 *          schema:
 *            type: string
 *      responses:
 *        200:
 *          description:  Successful response.
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                  phone_number:
 *                      type: string
 *                      description: Phone number of the associated visitor
 * 
 *        401:
 *          description: Unauthorized. Please login.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized. Please login.
 * 
 *        403:
 *          description: Forbidden. Access denied. You are not authorized to view this visitor pass.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Forbidden. Access denied. You are not authorized to view this visitor pass.
 * 
 *        404:
 *          description: Visitor pass not found.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Visitor pass not found.
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'          
 */



/**
 * @swagger
 *  /security/user/approval:
 *    patch:
 *      summary: Approve a user (Admin/Security)
 *      description: |
 *        Approves a pending user by their ID if the requester is an admin or security personnel.
 *      tags:
 *        - Security
 *      security:
 *        - Authorization: []
 *      requestBody:
 *          required: true
 *          description: The ID of the pending user to approve.
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                  id:
 *                      type: string
 *                      example: 614f5f37600b29604c4cd1fa
 *      responses:
 *        200:
 *          description: User approved successfully.
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                  username:
 *                    type: string
 *                    description: Username of the approved user.
 *                  approval:
 *                    type: boolean
 *                    description: Approval status of the user.
 *                  message:
 *                    type: string
 *                    description: Confirmation message.
 *                    example: User has been approved
 * 
 *        400:
 *          description: User has already been approved.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: User has already been approved
 * 
 *        403:
 *          description: Unauthorized access.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Admin and security access only
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'
 */

/**
 * @swagger
 *  /security/read/user/pending:
 *    get:
 *      summary: Get pending users (Admin/Security)
 *      description: Retrieves a list of pending users for admin or security personnel.
 *      tags:
 *        - Security
 *      security:
 *        - Authorization: []
 *      responses:
 *        200:
 *          description: Successful response containing a list of pending users.
 *          content:
 *            application/json:
 *              schema:
 *                type: array
 *                items:
 *                  $ref: '#/components/schemas/User'
 * 
 *        401:
 *          description: Unauthorized. Please login.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized. Please login.
 * 
 *        403:
 *          description: Unauthorized access for non-admin/non-security users.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Forbidden. Access denied. Admin and security access only
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'          
 */

/**
 * @swagger
 *  /security/read/pass:
 *    post:
 *      summary: Get a list of visitor passes based on criteria (Security/Admin)
 *      description: Retrieve a list of visitor passes based on the provided criteria. Requires admin or security role.
 *      tags:
 *        - Security
 *      security:
 *        - Authorization: []
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            example:
 *              _id: "123456"
 *      responses:
 *        200:
 *          description: Successful response with a list of visitor passes
 *          content:
 *            application/json:
 *              schema:
 *                type: array
 *                items:
 *                  $ref: '#/components/schemas/Pass'
 *        401:
 *          description: Unauthorized, please login
 *        403:
 *          description: Unauthorized, admin and security access only
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                 $ref: '#components/schemas/errormessage'
 *                
 */






/**
 * @swagger
 *  /security/read/resident:
 *    post:
 *      summary: Get details of a resident by resident number (Security/Admin)
 *      description: Retrieve details of a resident based on the resident number. Requires admin or security role.
 *      tags:
 *        - Security
 *      security:
 *        - Authorization: []
 *      requestBody:
 *          description: Resident details request
 *          required: true
 *          content:
 *              application/json:
 *                  schema:
 *                      type: object
 *                      properties:
 *                          resident_number:
 *                              type: integer
 *                              description: Resident number
 *                              example: 1
 *      responses:
 *        200:
 *          description: Successful response with a list of residents
 *          content:
 *            application/json:
 *              schema:
 *                type: array
 *                items:
 *                  $ref: '#/components/schemas/Resident'
 * 
 *        401:
 *          description: Unauthorized. Please login.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized. Please login.
 * 
 *        403:
 *          description: Unauthorized access for non-admin/non-security users.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Forbidden. Access denied. Admin and security access only
 *        404:
 *          description: Resident not found
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'          
 */

/**
 * @swagger
 *  /security/pass/approval/{id}:
 *    patch:
 *      summary: Approve a visitor pass (Security/Admin)
 *      description: Approve a pending visitor pass. Requires admin or security role.
 *      tags:
 *        - Security
 *      security:
 *        - Authorization: []
 *      parameters:
 *        - in: path
 *          name: id
 *          required: true
 *          description: ID of the pending visitor pass
 *          schema:
 *            type: string
 *      responses:
 *        200:
 *          description: Visitor pass has been approved
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *              example:
 *                  Pass: "approved_pass"
 *                  message: "Pass has been approved"
 * 
 *        401:
 *          description: Unauthorized. Please login.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized. Please login.
 * 
 *        403:
 *          description: Forbidden. Access denied. You are not authorized to view this visitor pass.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Forbidden. Access denied. You are not authorized to view this visitor pass.
 * 
 *        404:
 *          description: Pending visitor pass not found
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Pending visitor pass not found
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'          
 */

/**
 * @swagger
 *  /security/pass/checkin/{id}:
 *    patch:
 *      summary: Check in a visitor pass (Security/Admin)
 *      description: Check in a visitor pass based on the provided pass ID. Requires admin or security role.
 *      tags:
 *        - Security
 *      security:
 *        - Authorization: []
 *      parameters:
 *        - in: path
 *          name: id
 *          required: true
 *          description: Visitor pass ID
 *          schema:
 *            type: string
 *      responses:
 *        200:
 *          description: Successful response with the updated visitor pass details
 *          content:
 *            application/json:
 *              schema:
 *                $ref: '#components/schemas/Pass'  
 *                  
 * 
 *        401:
 *          description: Unauthorized. Please login.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized. Please login.
 * 
 *        403:
 *          description: Unauthorized, admin and security access only
 * 
 *        404:
 *          description: Visitor pass not found
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Visitor pass not found
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'          
 */

/**
 * @swagger
 *  /security/pass/checkout/{id}:
 *    patch:
 *      summary: Check out a visitor pass (Security/Admin)
 *      description: Check out a visitor pass based on the provided pass ID. Requires admin or security role.
 *      tags:
 *        - Security
 *      security:
 *        - Authorization: []
 *      parameters:
 *        - in: path
 *          name: id
 *          required: true
 *          description: Visitor pass ID
 *          schema:
 *            type: string
 *      responses:
 *        200:
 *          description: Successful response with the updated visitor pass details
 *          content:
 *            application/json:
 *              schema:
 *                $ref: '#components/schemas/Pass'  
 *                  
 * 
 *        401:
 *          description: Unauthorized. Please login.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized. Please login.
 * 
 *        403:
 *          description: Unauthorized, admin and security access only
 * 
 *        404:
 *          description: Visitor pass not found
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Visitor pass not found
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'          
 */




/**
 * @swagger
 *  /admin/dump:
 *    get:
 *      summary: Retrieve all data for admin
 *      description: |
 *        Retrieves data from the database for admin purposes.
 *        This endpoint is only accessible to admin users.
 *      tags:
 *        - For Admin Only
 *      security:
 *        - Authorization: []
 *      responses:
 *        200:
 *          description: This endpoint is only accessible to admin users.
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                  Users:
 *                    type: array
 *                    item:
 *                      $ref: '#/components/schemas/User'
 *                  Visitors:
 *                    type: array
 *                    item:
 *                      $ref: '#/components/schemas/Visitor'
 *                  Visitor_Passes:
 *                    type: array
 *                    item:
 *                      $ref: '#/components/schemas/Pass'
 *        401:
 *          description: Unauthorized. Please login.
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized. Please login.
 * 
 *        403:
 *          description: Forbidden - User does not have admin rights
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Forbidden - User does not have admin rights
 *
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'          
 */


/**
 * @swagger
 *  /admin/read/{collections}:
 *    post:
 *      summary: Read data from different collections
 *      description: |
 *        Allows an admin user to retrieve data from different collections based on the provided `collections` query parameter and filters specified in the request body.
 *      tags:
 *        - For Admin Only
 *      security:
 *        - Authorization: []
 *      parameters:
 *        - in: path
 *          name: collections
 *          required: true
 *          description: Name of the collection to retrieve data from(select from User, Visitor, Visitor_Pass, Resident)
 *          type: string
 *          
 *      requestBody:
 *        description: Filters to apply for the query. This should match the schema of the respective collections.
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              example:
 *                field1: value1
 *                field2: value2
 *              
 *              
 *      responses:
 *        200:
 *          description: Successful response with query results
 *          content:
 *            application/json:
 *              schema:
 *                type: array
 *                items:
 *                  type: object
 * 
 *        400:
 *          description: Invalid or missing parameter(s)
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Invalid or missing parameter(s)
 * 
 *        403:
 *          description: Unauthorized ,Admin access only
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized ,Admin access only
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'
 */


/**
 * @swagger
 *  /admin/update/{id}:
 *    post:
 *      summary: Update any document based on ID and collection
 *      description: |
 *        Admin-only endpoint to update documents by ID in specified collections.
 *      tags:
 *        - For Admin Only
 *      security:
 *        - Authorization: []
 *      parameters:
 *        - in: path
 *          name: id
 *          required: true
 *          description: ID of the document to update
 *          schema:
 *            type: string
 *        - in: query
 *          name: collections
 *          required: true
 *          description: Name of the collection (User, Visitor,Visitor_Pass, or Resident)
 *          schema:
 *             type: string
 *             enum: 
 *              - User
 *              - Visitor
 *              - Visitor_Pass
 *              - Resident
 * 
 *      requestBody:
 *          name: update
 *          required: true
 *          description: Fields to update in the document
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *              example: 
 *                _id: value1
 *                field2: value2
 *      responses:
 *        200:
 *          description: Successful update
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                  _id:
 *                    type: string
 *                    description: ID of the updated document
 *                  field1:
 *                    type: string
 *                    description: Updated field 1
 *                  field2:
 *                    type: string
 *                    description: Updated field 2
 * 
 *        400:
 *          description: Invalid or missing parameter(s)
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Invalid or missing parameter(s)
 * 
 *        403:
 *          description: Unauthorized, Admin access only
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized, Admin access only
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'
 */


/**
 * @swagger
 *  /admin/delete/all/user/{id}:
 *    delete:
 *      summary: Delete a user and associated data
 *      description: |
 *        Deletes a user and related data from the Visitor and Pass collections.
 *      tags:
 *        - For Admin Only
 *      security:
 *        - Authorization: []
 *      parameters:
 *        - in: path
 *          name: id
 *          required: true
 *          description: ID of the user to delete
 *          schema:
 *            type: string
 *       
 *      responses:
 *        200:
 *          description: User and associated data deleted successfully
 * 
 *        400:
 *          description: Invalid request
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Invalid request
 * 
 *        403:
 *          description: Unauthorized, Admin access only
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized, Admin access only
 * 
 *        404:
 *          description: User not found
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: User not found
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'
 */


/**
 * @swagger
 *  /admin/delete/visitor/{id}:
 *    delete:
 *      summary: Delete a visitor and associated visitor_pass documents (Admin only)
 *      description: |
 *        Delete a visitor and associated visitor_pass documents (Admin only)
 *      tags:
 *        - For Admin Only
 *      security:
 *        - Authorization: []
 *      parameters:
 *        - in: path
 *          name: id
 *          required: true
 *          description: ID of the visitor to be deleted
 *          schema:
 *            type: string
 *       
 *      responses:
 *        200:
 *          description:  Visitor and associated data deleted successfully
 * 
 *        403:
 *          description: Unauthorized, Admin access only
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Unauthorized, Admin access only
 * 
 *        404:
 *          description: Visitor not found
 *          content:
 *            text/plain:
 *              schema:
 *                type: string
 *                example: Visitor not found
 *        500:
 *          description: Internal server error
 *          content:
 *            application/json:
 *              schema:
 *                  $ref: '#components/schemas/errormessage'
 */

/**
 * @swagger
 *  components:
 *      schemas:
 *          registerinfo:
 *              type: object
 *              properties:
 *                  username:
 *                      type: string
 *                  password:
 *                      type: string
 *                  name:
 *                      type: string
 * 
 * 
 *          registersuccessful:
 *              type: object
 *              properties:
 *                  username:
 *                      type: string
 *                  name:
 *                      type: string
 *                  message:
 *                      type: string
 *                      description: Additional message
 * 
 *          errormessage:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  example: Internal server error occurred
 * 
 *          jwtinfo:
 *            type: object
 *            properties:
 *              username:
 *                type: string
 *              user_id: 
 *                type: string
 *                format: uuid
 * 
 *          Resident:
 *              type: object
 *              properties:
 *                  resident_number:
 *                      type: number
 *                  resident_name:
 *                      type: string
 *                  resident_phone_number:
 *                      type: string
 *                  resident_address:
 *                      type: string
 *          User:
 *              type: object
 *              properties:
 *                  username:
 *                      type: string
 *                  password:
 *                      type: string
 *                  name:
 *                      type: string 
 *                  role:
 *                      type: string
 *                  visitor_id:
 *                      type: array
 *                      items:
 *                          type: string
 *                          format: uuid
 *                  approval:
 *                      type: boolean
 *                  login_status:
 *                      type: boolean
 * 
 *          Visitor:
 *              properties:
 *                  full_name:
 *                      type: string
 *                  phone_number:
 *                      type: string
 *                  email:
 *                      type: string 
 *                  license_number:
 *                      type: string
 *                  user_id:
 *                      type: string
 *                      format: uuid
 *                  visitor_pass_id:
 *                      type: array
 *                      items:
 *                        type: string
 *                        format: uuid
 * 
 *          Pass:
 *              properties:
 *                  visitor_id:
 *                      type: string
 *                      format: uuid
 *                  resident_number:
 *                      type: number
 *                  purpose_of_visit:
 *                      type: string
 *                  approval:
 *                      type: boolean 
 *                  checkin_time:
 *                      type: string
 *                      format: date-time
 *                  checkout_time:
 *                      type: string
 *                      format: date-time
 *                  remarks:
 *                      type: string
 */