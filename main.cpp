

#include <iostream>
#include <string>
#include <unordered_map>
#include <sstream>
#include <vector>


#include "./crow/include/crow.h"

#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>


#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <iomanip>









std::string host = "localhost";
std::string user = "hanif";
std::string password = "mysqlpassword";





enum Request{
    LOGIN,CREATE_ACCOUNT,CREATE,READ,UPDATE,DELETE,NEW_SESSION
};



int get_last_inserted_id(sql::Statement *stmt){

    sql::ResultSet *result = stmt->executeQuery("SELECT LAST_INSERT_ID()");
    
    if (result->next()) {
        return result->getInt(1);

    }else{
        return -1;
    }

    delete result;

    
};





std::string sign(std::string data){

    std::string secrete_key = "s4heoifh83u42";

    unsigned char* result;

    unsigned int len = EVP_MAX_MD_SIZE;

    result = HMAC(EVP_sha256(), secrete_key.c_str(), secrete_key.length(), (unsigned char*)data.c_str(), data.length(), nullptr, nullptr);

    std::ostringstream oss;
    for (unsigned int i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);
    }
    return oss.str();


};




bool verify(const std::string hash, const std::string data) {

    if (sign(data) == hash){
        return true;
    };

    return false;
    
};







std::unordered_map<std::string, std::string> query(Request request, std::unordered_map<std::string, std::string> options){

    std::unordered_map<std::string, std::string> message;

    try{
        sql::mysql::MySQL_Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;


        driver = sql::mysql::get_mysql_driver_instance();
        con = driver->connect(host, user, password);
        con->setSchema("todo");

        stmt = con->createStatement();



        ////////////////////////////////////



        
        

        if(LOGIN == request){

            std::ostringstream fstring;

            fstring<<"SELECT id,username,password FROM users WHERE username='"<<options["username"]<<"'";

            std::string the_query = fstring.str();



            res=stmt->executeQuery(the_query);



            

            if (res->next()){

                std::string the_id, the_password;
                
                the_id = res->getString("id");
                the_password = res->getString("password");

                

                if (the_password == options["password"]){
                
                    
                    message["the_id"] = the_id;
                    message["status"] = "success";
                    

                }else{
                    message["status"] = "message";
                    message["msg"] = "Incorrect username or password";

                }

            }else{

                message["status"] = "message";
                message["msg"] = "Username not found";
            }


            delete res;
            






        }else if(CREATE_ACCOUNT == request){

            std::ostringstream fstring;

            fstring<<"INSERT INTO users(username,password) VALUES('"<<options["username"]<<"','"<<options["password"]<<"')";

            std::string the_query = fstring.str();
            
            stmt->execute(the_query);
        

            int last_id = get_last_inserted_id(stmt);

            if(last_id == -1){
                message["status"] = "message";
                message["msg"] = "Something went wrong";
            }else{
                message["the_id"] = std::to_string(last_id);
                message["status"] = "success";
            }
            
        }else if(CREATE == request){
            std::cout<<"this";
        }else if(READ == request){
            std::cout<<"this";
        }else if(UPDATE == request){
            std::cout<<"this";
        }else if(DELETE == request){
            std::cout<<"this";
        }else if(NEW_SESSION == request){
            std::ostringstream fstring;

            fstring<<"INSERT INTO sessions(uid) VALUES("<<options["id"]<<")";

            std::string the_query = fstring.str();
            
            stmt->execute(the_query);
        

            int last_id = get_last_inserted_id(stmt);

            if(last_id == -1){
                message["status"] = "message";
                message["msg"] = "Something went wrong";
            }else{
                message["the_id"] = std::to_string(last_id);
                message["status"] = "success";
            }
            
        };

        
        

        // //////////////////////////////////////////

        delete stmt;
        delete con;


        return message;

    }catch (sql::SQLException &e){
        // std::cout<<e.what();

        if (e.getErrorCode() == 1062) {
            message["status"] = "message";
            message["msg"] = "username is already taken";
        }else{
            message["status"] = "message";
            message["msg"] = "something went wrong, try again";
        }

        return message;
    };
};





std::map<std::string, std::string> parse_cookies(const std::string& cookie_header) {
    std::map<std::string, std::string> cookies;
    std::istringstream cookie_stream(cookie_header);
    std::string cookie;

    while (std::getline(cookie_stream, cookie, ';')) {
        auto pos = cookie.find('=');
        if (pos != std::string::npos) {
            std::string name = cookie.substr(0, pos);
            std::string value = cookie.substr(pos + 1);
            cookies[name] = value;
        }
    }

    return cookies;
}







struct cookie_parser{
    struct context{
        std::map<std::string, std::string> cookies;
        std::map<std::string, std::string> set_cookies;
        bool set = false;
    };

    void before_handle(crow::request& req, crow::response& res, context& ctx){
        auto cookie_header = req.get_header_value("Cookie");
        

        if(!cookie_header.empty()){
            try{
                ctx.cookies = parse_cookies(cookie_header);

                auto thedata = crow::json::load(ctx.cookies["data"]);

                crow::json::wvalue data (thedata);


                std::string first = data["signature"].dump();
                std::string second = data["uid"].dump();

                first = first.substr(1, first.length() - 2);
                second = second.substr(1, second.length() - 2);

                bool is_cookie_valid = verify(first,second);
                

                if(is_cookie_valid){
                    ctx.cookies["status"] = "valid";
                    ctx.cookies["uid"] = second;

                }else{
                    ctx.cookies["status"] = "invalid";
                }
                

            }catch(const std::exception& e){
                ctx.cookies["status"] = "not_compatible";
            }

        }else{
            ctx.cookies["status"] = "empty";
        }
    }

    void after_handle(crow::request& req, crow::response& res, context& ctx){
        if (ctx.set){
            for (const auto& cookie : ctx.set_cookies) {
                res.add_header("Set-Cookie", cookie.first + "=" + cookie.second + "; Path=/; HttpOnly");
            }
        }
    }
};








void set_cookie(cookie_parser::context& ctx, const std::string& value, const std::string& signature) {

    std::unordered_map<std::string, std::string> uid_signature;

    uid_signature["uid"] = value;
    uid_signature["signature"] = signature;


    crow::json::wvalue store;

    for (const auto& pair : uid_signature) {
        store[pair.first] = pair.second;
    };

    ctx.set_cookies["data"] = store.dump();

    ctx.set = true;
}




std::string get_cookie(cookie_parser::context& ctx, const std::string& key) {
    if (ctx.cookies.find(key) != ctx.cookies.end()) {
        return ctx.cookies[key];
    }
    return "Cookie not found";
}




















std::unordered_map<std::string, std::string> access(std::string task, std::string username, std::string password, cookie_parser::context& ctx){

    std::unordered_map<std::string, std::string> options;


    options["username"] = username;
    options["password"] = password;
    
    std::unordered_map<std::string, std::string> json_string;

    if(task == "1"){
        json_string = query(LOGIN,options);
    }else if(task == "2"){
        json_string = query(CREATE_ACCOUNT,options);
    }


    if (json_string["status"] == "success"){
        
        std::unordered_map<std::string, std::string> session_id;

        session_id = query(NEW_SESSION,std::unordered_map<std::string, std::string>{{"id",json_string["the_id"]}});
        
    

        set_cookie(ctx, session_id["the_id"], sign(session_id["the_id"]));
   
   
    }

    json_string.erase("the_id");

    return json_string;
    

}













int main()
{
    crow::App<cookie_parser> app;


    
    // CROW_ROUTE(app, "/")([](){
    //     auto page = crow::mustache::load_text("index.html");
        
    //     return page;
    // });

    
    CROW_ROUTE(app, "/access/").methods(crow::HTTPMethod::POST)([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);

        auto json_data = crow::json::load(req.body);

        std::unordered_map<std::string, std::string> query_response;
        
        query_response = access(json_data["task"].s(),json_data["username"].s(),json_data["password"].s(), ctx);
        

        crow::json::wvalue response_data;


        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };



        // res.add_header("Content-Type", "application/json");

        res.write(response_data.dump());
        res.end();
    });








    // CROW_ROUTE(app, "/create/").methods(crow::HTTPMethod::POST)([](const crow::request& req){

    //     auto json_data = crow::json::load(req.body);

    
    //     return "page";
    // });



    app.bindaddr("192.168.122.143").port(18080).multithreaded().run();


    return 0;
}