#!/usr/bin/env python
# -*- coding: utf-8 -*-

from abc import ABCMeta, abstractmethod
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
import re
import scoring
from dateutil.relativedelta import relativedelta

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(metaclass=ABCMeta):

    def __init__(self, required=False, nullable=False):
        self.errors = {'required': "This field is required.",
                       'nullable': "This field can't be null"}
        self.required = required
        self.nullable = nullable

    @abstractmethod
    def validate(self, value):
        raise NotImplementedError

    @abstractmethod
    def no_value(self, value):
        raise NotImplementedError

    def transform(self, value):
        return value


class CharField(Field):
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors['invalid_type'] = 'Value type must be str'

    def validate(self, value):
        if not isinstance(value, str):
            raise TypeError(self.errors["invalid_type"])

    def no_value(self, value):
        return not value


class ArgumentsField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors['invalid_type'] = 'Value type must be dict'
        
    def validate(self, value):
        if not isinstance(value, dict):
            raise TypeError(self.errors["invalid_type"])

    def no_value(self, value):
        return not value


class EmailField(CharField):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors['invalid_value'] = "String must contain @"
        
    def validate(self, value):
        super().validate(value)
        if self.no_value(value):
            return

        if "@" not in value:
            raise ValueError(self.errors['invalid_value'])

    def no_value(self, value):
        return not value


class PhoneField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors['invalid_type'] = "Value type must be str or int"
        self.errors['invalid_value'] = "First digit have to be 7"
        self.errors['invalid_value_len'] = "Len of phone number must be 11"
        
    def validate(self, value):
        if not isinstance(value, (int, str)):
            raise TypeError(self.errors['invalid_type'])

        if self.no_value(value):
            return

        value_str = str(value)
        if len(value_str) != 11:
            raise ValueError(self.errors['invalid_value_len'])

        if not value_str.startswith("7"):
            raise ValueError(self.errors['invalid_value'])

    def no_value(self, value):
        return not value


class DateField(CharField):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors['invalid_format'] = "Value format must be DD.MM.YYYY"
        self.errors['invalid_date'] = "Not valid date format"
        

    def _to_datetime(self, value):
        return datetime.datetime.strptime(value, "%d.%m.%Y")

    def validate(self, value):
        if self.no_value(value):
            return 

        super().validate(value)

        if not re.match(r"\d{2}\.\d{2}.\d{4}", value):
            raise ValueError(self.errors['invalid_format'])

        try:
            self._to_datetime(value)
        except (TypeError, ValueError):
            raise ValueError(self.errors['invalid_date'])

    def no_value(self, value):
        return not value

    def transform(self, value):
        return self._to_datetime(value)


class BirthDayField(DateField):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors['invalid_year'] = "Age must be less than 70 years"
        self.errors['back_to_the_future'] = "Date mustn't be in the future"

    def validate(self, value):
        super().validate(value)

        if self.no_value(value):
            return

        now = datetime.datetime.now()
        date_value = self._to_datetime(value)
        delta = relativedelta(now, date_value)
        years_delta = delta.years
        if not (0 <= years_delta < 70):
            raise ValueError(self.errors['invalid_year'])

        if now < date_value:
            raise ValueError(self.errors['back_to_the_future'])

    def no_value(self, value):
        return not value


class GenderField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors['invalid_type'] = "Value type must be int"
        self.errors['invalid_value'] = "Value must be 0, 1 or 2"

    def validate(self, value):
        if not isinstance(value, int):
            raise TypeError(self.errors['invalid_type'])

        if self.no_value(value):
            return

        if value not in GENDERS:
            raise ValueError(self.errors['invalid_value'])

    def no_value(self, value):
        return False


class ClientIDsField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors['invalid_type'] = "Value type must be list"
        self.errors['invalid_value'] = "Type of elements of list must be int"

    def validate(self, value):
        if not isinstance(value, list):
            raise TypeError(self.errors['invalid_type'])

        if self.no_value(value):
            return

        for elem in value:
            if not isinstance(elem, int):
                raise ValueError(self.errors['invalid_value'])

    def no_value(self, value):
        return not value

class AbstractRequest(metaclass=ABCMeta):
    
    def __init__(self, **kwargs):
        
        if not hasattr(self, 'errors'):
            self.errors = {}
        self.errors['required'] = "Field {} is required"
        self.errors['nullable'] = "Field {} can't be empty"
        self.errors['unexpected'] = "Field {} is unexpected"

        self.request_errors = {}
        self.field_classes = {}
        for field_name in dir(self):
            field_value = getattr(self, field_name, None)
            if isinstance(field_value, Field):
                self.field_classes[field_name] = field_value
                setattr(self, field_name, None)

        for field_name, field_value in kwargs.items():
            setattr(self, field_name, field_value)

        self.validate()

        if not self.request_errors:
            for field_name in dir(self):
                if (field_name in self.field_classes) and (getattr(self, field_name)):
                    prepared_value = self.field_classes[field_name].transform(
                        getattr(self, field_name)
                    )
                    setattr(self, field_name, prepared_value)

    def validate(self):
        for field_name, field_cls in self.field_classes.items():
            field_value = getattr(self, field_name, None)

            if field_cls.required:
                if field_value is None:
                    msg = self.errors["required"].format(field_name)
                    self.request_errors[field_name] = msg
                    continue

            if not field_cls.nullable:
                if not field_value:
                    msg = self.errors["nullable"].format(field_name)
                    self.request_errors[field_name] = msg
                    continue

            if field_value != None: 
                try:
                    field_cls.validate(field_value)
                except (TypeError, ValueError) as ex:
                    self.request_errors[field_name] = str(ex)


class ClientsInterestsRequest(AbstractRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def get_answer(self, store, context, is_admin):
        context["nclients"] = len(self.client_ids)
        result = {}
        for cid in self.client_ids:
            result[str(cid)] = scoring.get_interests(store=store, cid=cid)

        return result


class OnlineScoreRequest(AbstractRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, **kwargs):
        self.field_pairs = [
            ("phone", "email"),
            ("first_name", "last_name"),
            ("gender", "birthday")
        ]
        pairs_str = ", ".join(["(%s, %s)" % pair for pair in self.field_pairs])
        if not hasattr(self, 'errors'):
            self.errors = {}
        self.errors['invalid_pairs'] = "Request must have at least one pair with non-empty values of: {}".format(pairs_str)
        super().__init__(**kwargs)

    def validate(self):
        
        super().validate()

        is_valid = False
        for pair in self.field_pairs:
            field_1_value = getattr(self, pair[0], None)
            field_1_empty = self.field_classes[pair[0]].no_value(field_1_value)
            field_1_empty = field_1_value is None or field_1_empty

            field_2_value = getattr(self, pair[1], None)
            field_2_empty = self.field_classes[pair[1]].no_value(field_2_value)
            field_2_empty = field_1_value is None or field_2_empty

            if not(field_1_empty or field_2_empty):
                if (pair[0] not in self.errors.keys()) and (pair[1] not in self.errors.keys()): 
                    is_valid = True
                    break
               
        if not is_valid:
            self.request_errors["invalid_pairs"] = self.errors["invalid_pairs"]
        

    def get_answer(self, store, context, is_admin):
        filled_field_names = [
            field_name
            for field_name in self.field_classes.keys()
            if getattr(self, field_name, None) is not None
        ]
        context["has"] = filled_field_names

        if is_admin:
            result = 42
        else:
            result = scoring.get_score(
                store=store,
                phone=self.phone, email=self.email,
                birthday=self.birthday, gender=self.gender,
                first_name=self.first_name, last_name=self.last_name
            )

        return {"score": result}


class MethodRequest(AbstractRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((str(datetime.datetime.now().strftime("%Y%m%d%H")) + str(ADMIN_SALT)).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((str(request.account) + str(request.login) + str(SALT)).encode('utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False

def method_handler(request, context, store):
    
    handlers = {
        "online_score": OnlineScoreRequest,
        "clients_interests": ClientsInterestsRequest
    }
    
    methodrequest = MethodRequest(**request["body"])
    

    if methodrequest.request_errors:
        return methodrequest.request_errors, INVALID_REQUEST
        
    if not check_auth(methodrequest):
        return ERRORS[FORBIDDEN], FORBIDDEN

    if methodrequest.method not in handlers:
        msg = "Method {} isn't specified".format(methodrequest.method)
        return msg, NOT_FOUND

    handler = handlers[methodrequest.method](**methodrequest.arguments)
    if handler.request_errors:
        return handler.request_errors, INVALID_REQUEST
        
        
    return handler.get_answer(store, context, methodrequest.is_admin), OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
